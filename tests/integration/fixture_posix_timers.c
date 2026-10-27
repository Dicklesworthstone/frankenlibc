#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mqueue.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Every case runs in a separate process. Callback state remains alive until
 * process exit, including notifications already pending at timer_delete. */
#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "posix-timers:%s:%d: %s (errno=%d)\n", \
                __func__, __LINE__, #expression, errno); \
        _Exit(1); \
    } \
} while (0)

struct state {
    sem_t ready;
    sem_t release;
    sem_t finished;
    sem_t cleanup;
    sem_t destructor;
    _Atomic int calls;
    _Atomic int active;
    _Atomic int peak;
    timer_t timer;
    timer_t nested;
    pthread_key_t key;
    pthread_t creator;
    pthread_t callback;
    size_t stack_size;
    size_t guard_size;
    cpu_set_t affinity;
};
static struct state state;
static struct state fork_state;
static const char *host_library;

static void initialize(struct state *s) {
    CHECK(sem_init(&s->ready, 0, 0) == 0);
    CHECK(sem_init(&s->release, 0, 0) == 0);
    CHECK(sem_init(&s->finished, 0, 0) == 0);
    CHECK(sem_init(&s->cleanup, 0, 0) == 0);
    CHECK(sem_init(&s->destructor, 0, 0) == 0);
    s->creator = pthread_self();
}

static void wait_for(sem_t *semaphore) {
    struct timespec deadline;
    CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += 5;
    while (sem_timedwait(semaphore, &deadline) != 0) CHECK(errno == EINTR);
}

static void wait_for_cpu(sem_t *semaphore) {
    struct timespec start, now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    volatile unsigned long work = 0;
    for (;;) {
        if (sem_trywait(semaphore) == 0) break;
        CHECK(errno == EAGAIN || errno == EINTR);
        for (unsigned i = 0; i < 10000; ++i) work += i;
        CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        CHECK(now.tv_sec - start.tv_sec < 5);
    }
    (void)work;
}

static int zero_time(struct timespec value) {
    return value.tv_sec == 0 && value.tv_nsec == 0;
}

static void arm(timer_t id, long initial_ns, long interval_ns) {
    struct itimerspec next = {
        .it_value = {.tv_nsec = initial_ns},
        .it_interval = {.tv_nsec = interval_ns},
    };
    CHECK(timer_settime(id, 0, &next, NULL) == 0);
}

static void counted_callback(union sigval value) {
    struct state *s = value.sival_ptr;
    CHECK(s == &state || s == &fork_state);
    CHECK(!pthread_equal(pthread_self(), s->creator));
    atomic_fetch_add_explicit(&s->calls, 1, memory_order_relaxed);
    CHECK(sem_post(&s->ready) == 0);
}

static timer_t thread_timer(clockid_t clock, void (*callback)(union sigval),
                            struct state *s, pthread_attr_t *attributes) {
    struct sigevent event = {
        .sigev_notify = SIGEV_THREAD,
        .sigev_notify_function = callback,
        .sigev_notify_attributes = attributes,
        .sigev_value.sival_ptr = s,
    };
    timer_t id;
    memset(&id, 0xa5, sizeof(id));
    CHECK(timer_create(clock, &event, &id) == 0);
    struct itimerspec initial;
    CHECK(timer_gettime(id, &initial) == 0);
    CHECK(zero_time(initial.it_value) && zero_time(initial.it_interval));
    CHECK(timer_getoverrun(id) == 0);
    return id;
}

static void one_shot(clockid_t clock, int absolute) {
    initialize(&state);
    state.timer = thread_timer(clock, counted_callback, &state, NULL);
    if (absolute) {
        struct itimerspec next = {0};
        CHECK(clock_gettime(clock, &next.it_value) == 0);
        next.it_value.tv_nsec += 2000000;
        if (next.it_value.tv_nsec >= 1000000000) {
            ++next.it_value.tv_sec;
            next.it_value.tv_nsec -= 1000000000;
        }
        CHECK(timer_settime(state.timer, TIMER_ABSTIME, &next, NULL) == 0);
    } else {
        arm(state.timer, 2000000, 0);
    }
    if (clock == CLOCK_PROCESS_CPUTIME_ID || clock == CLOCK_THREAD_CPUTIME_ID)
        wait_for_cpu(&state.ready);
    else
        wait_for(&state.ready);
    CHECK(atomic_load(&state.calls) == 1);
    struct itimerspec current;
    CHECK(timer_gettime(state.timer, &current) == 0);
    CHECK(zero_time(current.it_value) && zero_time(current.it_interval));
    CHECK(timer_getoverrun(state.timer) == 0);
    CHECK(timer_delete(state.timer) == 0);
}

static void periodic_disarm(void) {
    initialize(&state);
    state.timer = thread_timer(CLOCK_MONOTONIC, counted_callback, &state, NULL);
    arm(state.timer, 2000000, 2000000);
    for (int i = 0; i < 3; ++i) wait_for(&state.ready);
    CHECK(atomic_load(&state.calls) >= 3);
    struct itimerspec stopped = {0}, previous, current;
    CHECK(timer_settime(state.timer, 0, &stopped, &previous) == 0);
    CHECK(previous.it_interval.tv_sec == 0 && previous.it_interval.tv_nsec == 2000000);
    CHECK(timer_gettime(state.timer, &current) == 0);
    CHECK(zero_time(current.it_value) && zero_time(current.it_interval));
    CHECK(timer_getoverrun(state.timer) >= 0);
    /* Disarming does not promise to retract an already pending callback. */
    CHECK(timer_delete(state.timer) == 0);
}

static void overlapping_callback(union sigval value) {
    struct state *s = value.sival_ptr;
    int ticket = atomic_fetch_add(&s->calls, 1);
    if (ticket >= 2) return;
    int active = atomic_fetch_add(&s->active, 1) + 1;
    int peak = atomic_load(&s->peak);
    while (peak < active && !atomic_compare_exchange_weak(&s->peak, &peak, active)) {}
    CHECK(sem_post(&s->ready) == 0);
    wait_for(&s->release);
    atomic_fetch_sub(&s->active, 1);
    CHECK(sem_post(&s->finished) == 0);
}

static void overlap(void) {
    initialize(&state);
    state.timer = thread_timer(CLOCK_MONOTONIC, overlapping_callback, &state, NULL);
    arm(state.timer, 2000000, 2000000);
    wait_for(&state.ready);
    wait_for(&state.ready);
    CHECK(atomic_load(&state.peak) >= 2);
    CHECK(timer_delete(state.timer) == 0);
    CHECK(sem_post(&state.release) == 0);
    CHECK(sem_post(&state.release) == 0);
    wait_for(&state.finished);
    wait_for(&state.finished);
    CHECK(atomic_load(&state.active) == 0);
}

static void attribute_callback(union sigval value) {
    struct state *s = value.sival_ptr;
    pthread_attr_t attributes;
    size_t stack, guard;
    int detached, policy;
    struct sched_param parameter;
    cpu_set_t affinity;
    sigset_t mask;
    CHECK(pthread_getattr_np(pthread_self(), &attributes) == 0);
    CHECK(pthread_attr_getstacksize(&attributes, &stack) == 0);
    CHECK(pthread_attr_getguardsize(&attributes, &guard) == 0);
    CHECK(pthread_attr_getdetachstate(&attributes, &detached) == 0);
    CHECK(pthread_attr_destroy(&attributes) == 0);
    CHECK(stack == s->stack_size && guard == s->guard_size);
    CHECK(detached == PTHREAD_CREATE_DETACHED);
    CHECK(pthread_getschedparam(pthread_self(), &policy, &parameter) == 0);
    CHECK(policy == SCHED_OTHER && parameter.sched_priority == 0);
    CHECK(sched_getaffinity(0, sizeof(affinity), &affinity) == 0);
    CHECK(CPU_EQUAL(&affinity, &s->affinity));
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0);
    CHECK(sigismember(&mask, SIGUSR1) == 1 && sigismember(&mask, SIGUSR2) == 1);
    CHECK(sem_post(&s->ready) == 0);
}

static int same_file(const char *first, const char *second) {
    struct stat a, b;
    return stat(first, &a) == 0 && stat(second, &b) == 0 &&
        a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static void attributes_snapshot(int foreign) {
    struct attribute_api {
        int (*init)(pthread_attr_t *);
        int (*destroy)(pthread_attr_t *);
        int (*setdetachstate)(pthread_attr_t *, int);
        int (*setstacksize)(pthread_attr_t *, size_t);
        int (*setguardsize)(pthread_attr_t *, size_t);
        int (*setschedpolicy)(pthread_attr_t *, int);
        int (*setinheritsched)(pthread_attr_t *, int);
        int (*setschedparam)(pthread_attr_t *, const struct sched_param *);
        int (*setaffinity_np)(pthread_attr_t *, size_t, const cpu_set_t *);
        int (*setsigmask_np)(pthread_attr_t *, const sigset_t *);
    } api = {
        pthread_attr_init, pthread_attr_destroy, pthread_attr_setdetachstate,
        pthread_attr_setstacksize, pthread_attr_setguardsize, pthread_attr_setschedpolicy,
        pthread_attr_setinheritsched, pthread_attr_setschedparam,
        pthread_attr_setaffinity_np, pthread_attr_setsigmask_np,
    };
    void *host = NULL;
    if (foreign) {
        host = dlopen(host_library, RTLD_NOW | RTLD_LOCAL);
        CHECK(host != NULL);
#define HOST_ATTRIBUTE(name) do { \
        void *address = dlsym(host, "pthread_attr_" #name); \
        Dl_info owner; \
        CHECK(address != NULL && dladdr(address, &owner) != 0); \
        CHECK(same_file(owner.dli_fname, host_library)); \
        api.name = (__typeof__(api.name))address; \
    } while (0)
        HOST_ATTRIBUTE(init);
        HOST_ATTRIBUTE(destroy);
        HOST_ATTRIBUTE(setdetachstate);
        HOST_ATTRIBUTE(setstacksize);
        HOST_ATTRIBUTE(setguardsize);
        HOST_ATTRIBUTE(setschedpolicy);
        HOST_ATTRIBUTE(setinheritsched);
        HOST_ATTRIBUTE(setschedparam);
        HOST_ATTRIBUTE(setaffinity_np);
        HOST_ATTRIBUTE(setsigmask_np);
#undef HOST_ATTRIBUTE
    }
    initialize(&state);
    CHECK(sched_getaffinity(0, sizeof(state.affinity), &state.affinity) == 0);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    state.stack_size = 1024 * 1024;
    state.guard_size = 2 * page;
    pthread_attr_t *attributes = mmap(NULL, page, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(attributes != MAP_FAILED);
    CHECK(api.init(attributes) == 0);
    CHECK(api.setdetachstate(attributes, PTHREAD_CREATE_DETACHED) == 0);
    CHECK(api.setstacksize(attributes, state.stack_size) == 0);
    CHECK(api.setguardsize(attributes, state.guard_size) == 0);
    CHECK(api.setschedpolicy(attributes, SCHED_OTHER) == 0);
    CHECK(api.setinheritsched(attributes, PTHREAD_EXPLICIT_SCHED) == 0);
    struct sched_param parameter = {.sched_priority = 0};
    CHECK(api.setschedparam(attributes, &parameter) == 0);
    cpu_set_t selected;
    CPU_ZERO(&selected);
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, &state.affinity)) { CPU_SET(cpu, &selected); break; }
    }
    CHECK(CPU_COUNT(&selected) == 1);
    CHECK(api.setaffinity_np(attributes, sizeof(selected), &selected) == 0);
    sigset_t requested;
    sigemptyset(&requested);
    sigaddset(&requested, SIGUSR1);
    CHECK(api.setsigmask_np(attributes, &requested) == 0);
    /* GNU timer notifications copy standard attrs, omit GNU extension storage,
     * and start detached with application signals blocked. */
    state.timer = thread_timer(CLOCK_MONOTONIC, attribute_callback, &state, attributes);
    CHECK(api.destroy(attributes) == 0);
    CHECK(mprotect(attributes, page, PROT_NONE) == 0);
    arm(state.timer, 2000000, 0);
    wait_for(&state.ready);
    CHECK(timer_delete(state.timer) == 0);
    CHECK(munmap(attributes, page) == 0);
    if (host) CHECK(dlclose(host) == 0);
}

static void callback_cleanup(void *argument) {
    struct state *s = argument;
    CHECK(sem_post(&s->cleanup) == 0);
}

static void callback_destructor(void *argument) {
    struct state *s = argument;
    CHECK(sem_post(&s->destructor) == 0);
}

static void exiting_callback(union sigval value) {
    struct state *s = value.sival_ptr;
    CHECK(pthread_setspecific(s->key, s) == 0);
    pthread_cleanup_push(callback_cleanup, s);
    pthread_exit(NULL);
    pthread_cleanup_pop(0);
}

static void callback_exit(void) {
    initialize(&state);
    CHECK(pthread_key_create(&state.key, callback_destructor) == 0);
    state.timer = thread_timer(CLOCK_MONOTONIC, exiting_callback, &state, NULL);
    for (int round = 0; round < 2; ++round) {
        arm(state.timer, 2000000, 0);
        wait_for(&state.cleanup);
        wait_for(&state.destructor);
    }
    CHECK(timer_delete(state.timer) == 0);
    CHECK(pthread_key_delete(state.key) == 0);
}

static void cancelable_callback(union sigval value) {
    struct state *s = value.sival_ptr;
    s->callback = pthread_self();
    CHECK(pthread_setspecific(s->key, s) == 0);
    pthread_cleanup_push(callback_cleanup, s);
    if (atomic_load(&s->peak)) {
        /* Publish only after asynchronous cancellation is enabled. No library
         * calls occur in the spin, so cancellation must reach this thread. */
        _Static_assert(ATOMIC_INT_LOCK_FREE == 2, "callback readiness must be lock-free");
        CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) == 0);
        atomic_store_explicit(&s->active, 1, memory_order_release);
        while (atomic_load_explicit(&s->active, memory_order_relaxed) != 2)
            atomic_signal_fence(memory_order_seq_cst);
    } else {
        CHECK(sem_post(&s->ready) == 0);
        for (;;) CHECK(sem_wait(&s->release) == -1 && errno == EINTR);
    }
    pthread_cleanup_pop(0);
}

static void callback_cancel(void) {
    initialize(&state);
    CHECK(pthread_key_create(&state.key, callback_destructor) == 0);
    state.timer = thread_timer(CLOCK_MONOTONIC, cancelable_callback, &state, NULL);
    for (int asynchronous = 0; asynchronous < 2; ++asynchronous) {
        atomic_store(&state.peak, asynchronous);
        atomic_store(&state.active, 0);
        arm(state.timer, 2000000, 0);
        if (asynchronous) {
            struct timespec start, now;
            CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
            while (!atomic_load_explicit(&state.active, memory_order_acquire)) {
                CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
                CHECK(now.tv_sec - start.tv_sec < 5);
            }
        } else {
            wait_for(&state.ready);
        }
        CHECK(pthread_cancel(state.callback) == 0);
        wait_for(&state.cleanup);
        wait_for(&state.destructor);
    }
    CHECK(timer_delete(state.timer) == 0);
    CHECK(pthread_key_delete(state.key) == 0);
}

static void pending_sigpipe(void) {
    initialize(&state);
    sigset_t blocked, previous, pending;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPIPE);
    CHECK(pthread_sigmask(SIG_BLOCK, &blocked, &previous) == 0);
    state.timer = thread_timer(CLOCK_MONOTONIC, counted_callback, &state, NULL);
    CHECK(kill(getpid(), SIGPIPE) == 0);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1);
    arm(state.timer, 2000000, 0);
    wait_for(&state.ready);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1);
    struct timespec poll = {0};
    siginfo_t info;
    CHECK(sigtimedwait(&blocked, &info, &poll) == SIGPIPE);
    CHECK(info.si_code == SI_USER);
    CHECK(timer_delete(state.timer) == 0);
    CHECK(pthread_sigmask(SIG_SETMASK, &previous, NULL) == 0);
}

static void nested_callback(union sigval value) {
    struct state *s = value.sival_ptr;
    CHECK(timer_delete(s->nested) == 0);
    CHECK(sem_post(&s->ready) == 0);
}

static void deleting_callback(union sigval value) {
    struct state *s = value.sival_ptr;
    struct itimerspec current;
    CHECK(timer_gettime(s->timer, &current) == 0);
    CHECK(timer_getoverrun(s->timer) >= 0);
    CHECK(timer_delete(s->timer) == 0);
    s->nested = thread_timer(CLOCK_MONOTONIC, nested_callback, s, NULL);
    arm(s->nested, 2000000, 0);
}

static void self_delete(void) {
    initialize(&state);
    state.timer = thread_timer(CLOCK_MONOTONIC, deleting_callback, &state, NULL);
    arm(state.timer, 2000000, 0);
    wait_for(&state.ready);
}

static timer_t raw_timer(struct sigevent *event) {
    struct guarded_timer {
        uint64_t before;
        timer_t id;
        uint64_t after;
    } output = {.before = UINT64_C(0x7162738495a6b7c8),
                .after = UINT64_C(0x1827364554637281)};
    memset(&output.id, 0xa5, sizeof(output.id));
    CHECK(timer_create(CLOCK_MONOTONIC, event, &output.id) == 0);
    CHECK(output.before == UINT64_C(0x7162738495a6b7c8));
    CHECK(output.after == UINT64_C(0x1827364554637281));
    _Static_assert(sizeof(timer_t) <= sizeof(uint64_t), "Linux timer handle width");
    uint64_t handle = 0;
    memcpy(&handle, &output.id, sizeof(output.id));
    /* GNU/Linux non-thread timer handles zero-extend the kernel timer ID.
     * The previous veneer initialized only four bytes of an eight-byte timer_t. */
    CHECK((handle >> 32) == 0);
    return output.id;
}

static void raw_signal(int default_event) {
    int signo = default_event ? SIGALRM : SIGRTMIN;
    sigset_t set, previous;
    sigemptyset(&set);
    sigaddset(&set, signo);
    CHECK(pthread_sigmask(SIG_BLOCK, &set, &previous) == 0);
    struct sigevent event = {
        .sigev_notify = SIGEV_SIGNAL,
        .sigev_signo = signo,
        .sigev_value.sival_int = 0x6a17,
    };
    timer_t id = raw_timer(default_event ? NULL : &event);
    arm(id, 2000000, 0);
    struct timespec timeout = {.tv_sec = 5};
    siginfo_t info;
    int result;
    do { result = sigtimedwait(&set, &info, &timeout); } while (result < 0 && errno == EINTR);
    CHECK(result == signo && info.si_code == SI_TIMER);
    if (default_event) CHECK(info.si_value.sival_ptr == id);
    else CHECK(info.si_value.sival_int == 0x6a17);
    CHECK(timer_getoverrun(id) == 0);
    CHECK(timer_delete(id) == 0);
    CHECK(pthread_sigmask(SIG_SETMASK, &previous, NULL) == 0);
}

static void raw_none(void) {
    struct sigevent event = {.sigev_notify = SIGEV_NONE};
    timer_t id = raw_timer(&event);
    struct itimerspec current, old, next = {
        .it_value.tv_sec = 30,
        .it_interval.tv_nsec = 25000000,
    };
    CHECK(timer_settime(id, 0, &next, &old) == 0);
    CHECK(zero_time(old.it_value) && zero_time(old.it_interval));
    CHECK(timer_gettime(id, &current) == 0);
    CHECK(current.it_value.tv_sec >= 0 && current.it_value.tv_sec <= 30);
    CHECK(!zero_time(current.it_value));
    CHECK(current.it_interval.tv_nsec == 25000000);
    struct itimerspec disarmed = {0};
    CHECK(timer_settime(id, 0, &disarmed, &old) == 0);
    CHECK(old.it_interval.tv_nsec == 25000000);
    CHECK(timer_gettime(id, &current) == 0);
    CHECK(zero_time(current.it_interval));
    CHECK(current.it_value.tv_sec >= 0 && current.it_value.tv_sec <= 30);
    /* Linux kernels have historically retained the old SIGEV_NONE expiration
     * after disarm. Compare this normalized observation with live GNU in the
     * same runner invocation, rather than assuming the kernel has the fix.
     * See upstream report: linux-kernel@vger.kernel.org, 2026-10-11,
     * "posix-timers: Report a disarmed SIGEV_NONE timer as disarmed". */
    printf("posix-timers:none:disarmed-expiry-zero=%d\n", zero_time(current.it_value));
    CHECK(timer_delete(id) == 0);
}

static void fork_reset(void) {
    initialize(&state);
    state.timer = thread_timer(CLOCK_MONOTONIC, counted_callback, &state, NULL);
    arm(state.timer, 2000000, 0);
    wait_for(&state.ready);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        alarm(7);
        initialize(&fork_state);
        fork_state.timer = thread_timer(CLOCK_MONOTONIC, counted_callback, &fork_state, NULL);
        arm(fork_state.timer, 2000000, 0);
        wait_for(&fork_state.ready);
        CHECK(atomic_load(&fork_state.calls) == 1);
        CHECK(timer_delete(fork_state.timer) == 0);
        _Exit(0);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    arm(state.timer, 2000000, 0);
    wait_for(&state.ready);
    CHECK(atomic_load(&state.calls) == 2);
    CHECK(timer_delete(state.timer) == 0);
}

static void invalid_requests(void) {
    struct sigevent event = {.sigev_notify = SIGEV_NONE};
    timer_t id = NULL;
    errno = 0;
    CHECK(timer_create(INT_MAX, &event, &id) == -1 && errno == EINVAL);
    event.sigev_notify = INT_MAX;
    errno = 0;
    CHECK(timer_create(CLOCK_MONOTONIC, &event, &id) == -1 && errno == EINVAL);
    event.sigev_notify = SIGEV_SIGNAL;
    event.sigev_signo = 0;
    errno = 0;
    CHECK(timer_create(CLOCK_MONOTONIC, &event, &id) == -1 && errno == EINVAL);
    event.sigev_notify = SIGEV_NONE;
    id = raw_timer(&event);
    struct itimerspec invalid = {.it_value.tv_nsec = 1000000000}, current;
    errno = 0;
    CHECK(timer_settime(id, 0, &invalid, NULL) == -1 && errno == EINVAL);
    CHECK(timer_gettime(id, &current) == 0 && zero_time(current.it_value));
    CHECK(timer_delete(id) == 0);
}

static int kernel_timer_count(void) {
    FILE *file = fopen("/proc/self/timers", "r");
    if (!file && errno == ENOENT && !getenv("FRANKENLIBC_REQUIRE_TIMER_ACCOUNTING")) {
        fprintf(stderr, "posix-timers:kernel-accounting-unavailable\n");
        return -1;
    }
    CHECK(file != NULL);
    int count = 0;
    char line[512];
    while (fgets(line, sizeof(line), file)) if (!strncmp(line, "ID:", 3)) ++count;
    CHECK(!ferror(file));
    CHECK(fclose(file) == 0);
    return count;
}

static void lifetime_cycles(void) {
    int before = kernel_timer_count();
    for (int i = 0; i < 64; ++i) {
        timer_t id = thread_timer(CLOCK_MONOTONIC, counted_callback, &state, NULL);
        CHECK(timer_delete(id) == 0);
    }
    if (before >= 0) CHECK(kernel_timer_count() == before);
}

static pthread_barrier_t start_barrier;
static void *create_delete_worker(void *unused) {
    (void)unused;
    int rc = pthread_barrier_wait(&start_barrier);
    CHECK(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
    for (int i = 0; i < 32; ++i) {
        timer_t id = thread_timer(CLOCK_MONOTONIC, counted_callback, &state, NULL);
        CHECK(timer_delete(id) == 0);
    }
    return NULL;
}

static void concurrent_creation(void) {
    enum { WORKERS = 4 };
    pthread_t workers[WORKERS];
    int before = kernel_timer_count();
    CHECK(pthread_barrier_init(&start_barrier, NULL, WORKERS + 1) == 0);
    for (int i = 0; i < WORKERS; ++i)
        CHECK(pthread_create(&workers[i], NULL, create_delete_worker, NULL) == 0);
    int rc = pthread_barrier_wait(&start_barrier);
    CHECK(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
    for (int i = 0; i < WORKERS; ++i) CHECK(pthread_join(workers[i], NULL) == 0);
    CHECK(pthread_barrier_destroy(&start_barrier) == 0);
    if (before >= 0) CHECK(kernel_timer_count() == before);
}

/* Message queues share SIGEV_THREAD's public callback ABI with timers, but
 * use a different Linux delivery protocol and GNU signal-mask contract. */
struct queue_state {
    mqd_t queue;
    sem_t ready, release, finished, cleanup;
    _Atomic int calls;
    pthread_t creator;
    pthread_key_t key;
    size_t stack_size, guard_size;
    cpu_set_t affinity;
    int rearm_count;
};
static struct queue_state queues[6];
static _Atomic unsigned queue_serial;

static void queue_initialize(struct queue_state *s) {
    CHECK(sem_init(&s->ready, 0, 0) == 0);
    CHECK(sem_init(&s->release, 0, 0) == 0);
    CHECK(sem_init(&s->finished, 0, 0) == 0);
    CHECK(sem_init(&s->cleanup, 0, 0) == 0);
    s->creator = pthread_self();
}

static mqd_t queue_open(void) {
    char name[96];
    unsigned serial = atomic_fetch_add(&queue_serial, 1);
    CHECK(snprintf(name, sizeof(name), "/frankenlibc-notify-%ld-%u",
                   (long)getpid(), serial) > 0);
    struct mq_attr attr = {.mq_maxmsg = 4, .mq_msgsize = 32};
    mqd_t result = mq_open(name, O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK, 0600, &attr);
    CHECK(result != (mqd_t)-1);
    /* Remove only this newly-created kernel queue name; descriptors retain it. */
    CHECK(mq_unlink(name) == 0);
    return result;
}

static void queue_send(mqd_t queue) { CHECK(mq_send(queue, "event", 5, 7) == 0); }
static void queue_receive(mqd_t queue) {
    char message[32];
    unsigned priority;
    CHECK(mq_receive(queue, message, sizeof(message), &priority) == 5);
    CHECK(priority == 7 && !memcmp(message, "event", 5));
}

static struct sigevent queue_event(struct queue_state *s, void (*callback)(union sigval),
                                   pthread_attr_t *attributes) {
    struct sigevent event = {.sigev_notify = SIGEV_THREAD,
                            .sigev_notify_function = callback,
                            .sigev_notify_attributes = attributes,
                            .sigev_value.sival_ptr = s};
    return event;
}

static void queue_callback(union sigval value) {
    struct queue_state *s = value.sival_ptr;
    CHECK(s >= queues && s < queues + 6);
    CHECK(!pthread_equal(s->creator, pthread_self()));
    pthread_attr_t attributes;
    int detached;
    sigset_t mask;
    CHECK(pthread_getattr_np(pthread_self(), &attributes) == 0);
    CHECK(pthread_attr_getdetachstate(&attributes, &detached) == 0);
    CHECK(pthread_attr_destroy(&attributes) == 0);
    CHECK(detached == PTHREAD_CREATE_DETACHED);
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0);
    CHECK(sigismember(&mask, SIGUSR1) == 0 && sigismember(&mask, SIGUSR2) == 0);
    atomic_fetch_add(&s->calls, 1);
    CHECK(sem_post(&s->ready) == 0);
}

static void queue_quiet(struct queue_state *s) {
    struct timespec deadline;
    CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_nsec += 30000000;
    if (deadline.tv_nsec >= 1000000000) { ++deadline.tv_sec; deadline.tv_nsec -= 1000000000; }
    errno = 0;
    CHECK(sem_timedwait(&s->ready, &deadline) == -1 && errno == ETIMEDOUT);
}

static void queue_thread(void) {
    struct queue_state *s = &queues[0];
    queue_initialize(s);
    s->queue = queue_open();
    struct sigevent event = queue_event(s, queue_callback, NULL);
    CHECK(mq_notify(s->queue, &event) == 0);
    memset(&event, 0xa5, sizeof(event));
    queue_send(s->queue);
    wait_for(&s->ready);
    CHECK(atomic_load(&s->calls) == 1);
    queue_receive(s->queue);
    queue_send(s->queue);
    queue_quiet(s);
    CHECK(atomic_load(&s->calls) == 1);
    CHECK(mq_close(s->queue) == 0);
}

static void queue_attribute_callback(union sigval value) {
    struct queue_state *s = value.sival_ptr;
    pthread_attr_t attr;
    size_t stack, guard;
    cpu_set_t affinity;
    CHECK(pthread_getattr_np(pthread_self(), &attr) == 0);
    CHECK(pthread_attr_getstacksize(&attr, &stack) == 0);
    CHECK(pthread_attr_getguardsize(&attr, &guard) == 0);
    CHECK(pthread_attr_destroy(&attr) == 0);
    CHECK(stack == s->stack_size && guard == s->guard_size);
    CHECK(sched_getaffinity(0, sizeof(affinity), &affinity) == 0);
    CHECK(CPU_EQUAL(&affinity, &s->affinity));
    queue_callback(value);
}

static void queue_attributes(int foreign) {
    struct queue_state *s = &queues[0];
    queue_initialize(s);
    s->queue = queue_open();
    s->stack_size = 512 * 1024;
    s->guard_size = 8192;
    cpu_set_t available;
    CHECK(sched_getaffinity(0, sizeof(available), &available) == 0);
    CPU_ZERO(&s->affinity);
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, &available)) { CPU_SET(cpu, &s->affinity); break; }
    }
    void *host = foreign ? dlopen(host_library, RTLD_NOW | RTLD_LOCAL) : NULL;
    CHECK(!foreign || host != NULL);
    int (*init)(pthread_attr_t *) = foreign ? dlsym(host, "pthread_attr_init") : pthread_attr_init;
    int (*destroy)(pthread_attr_t *) = foreign ? dlsym(host, "pthread_attr_destroy") : pthread_attr_destroy;
    int (*stack)(pthread_attr_t *, size_t) = foreign ? dlsym(host, "pthread_attr_setstacksize") : pthread_attr_setstacksize;
    int (*guard)(pthread_attr_t *, size_t) = foreign ? dlsym(host, "pthread_attr_setguardsize") : pthread_attr_setguardsize;
    int (*affinity)(pthread_attr_t *, size_t, const cpu_set_t *) = foreign ? dlsym(host, "pthread_attr_setaffinity_np") : pthread_attr_setaffinity_np;
    int (*set_mask)(pthread_attr_t *, const sigset_t *) = foreign ? dlsym(host, "pthread_attr_setsigmask_np") : pthread_attr_setsigmask_np;
    CHECK(init && destroy && stack && guard && affinity && set_mask);
    pthread_attr_t attr;
    sigset_t blocked;
    CHECK(sigfillset(&blocked) == 0);
    CHECK(init(&attr) == 0);
    CHECK(stack(&attr, s->stack_size) == 0 && guard(&attr, s->guard_size) == 0);
    CHECK(affinity(&attr, sizeof(s->affinity), &s->affinity) == 0);
    CHECK(set_mask(&attr, &blocked) == 0);
    struct sigevent event = queue_event(s, queue_attribute_callback, &attr);
    CHECK(mq_notify(s->queue, &event) == 0);
    CHECK(destroy(&attr) == 0);
    memset(&attr, 0xa5, sizeof(attr));
    memset(&event, 0xa5, sizeof(event));
    queue_send(s->queue);
    wait_for(&s->ready);
    CHECK(mq_close(s->queue) == 0);
    if (host) CHECK(dlclose(host) == 0);
}

static void queue_defaults(void) {
    struct queue_state *s = &queues[0];
    queue_initialize(s);
    s->queue = queue_open();
    s->stack_size = 768 * 1024;
    s->guard_size = 12288;
    CHECK(sched_getaffinity(0, sizeof(s->affinity), &s->affinity) == 0);
    struct sigevent event = queue_event(s, queue_attribute_callback, NULL);
    CHECK(mq_notify(s->queue, &event) == 0);
    pthread_attr_t saved, attr;
    CHECK(pthread_getattr_default_np(&saved) == 0);
    CHECK(pthread_attr_init(&attr) == 0);
    CHECK(pthread_attr_setstacksize(&attr, s->stack_size) == 0);
    CHECK(pthread_attr_setguardsize(&attr, s->guard_size) == 0);
    CHECK(pthread_setattr_default_np(&attr) == 0);
    CHECK(pthread_attr_destroy(&attr) == 0);
    queue_send(s->queue);
    wait_for(&s->ready);
    CHECK(pthread_setattr_default_np(&saved) == 0);
    CHECK(pthread_attr_destroy(&saved) == 0);
    CHECK(mq_close(s->queue) == 0);
}

static void queue_rearm_callback(union sigval value) {
    struct queue_state *s = value.sival_ptr;
    int call = atomic_fetch_add(&s->calls, 1) + 1;
    if (call < s->rearm_count) {
        struct sigevent event = queue_event(s, queue_rearm_callback, NULL);
        CHECK(mq_notify(s->queue, &event) == 0);
    }
    queue_receive(s->queue);
    CHECK(sem_post(&s->ready) == 0);
}

static void queue_rearm(void) {
    struct queue_state *s = &queues[0];
    queue_initialize(s);
    s->queue = queue_open();
    s->rearm_count = 8;
    struct sigevent event = queue_event(s, queue_rearm_callback, NULL);
    CHECK(mq_notify(s->queue, &event) == 0);
    for (int i = 1; i <= s->rearm_count; ++i) {
        queue_send(s->queue);
        wait_for(&s->ready);
        CHECK(atomic_load(&s->calls) == i);
    }
    CHECK(mq_close(s->queue) == 0);
}

static void queue_busy(void) {
    struct queue_state *first = &queues[0], *second = &queues[1];
    queue_initialize(first);
    queue_initialize(second);
    first->queue = queue_open();
    struct sigevent event = queue_event(first, queue_callback, NULL);
    CHECK(mq_notify(first->queue, &event) == 0);
    event.sigev_value.sival_ptr = second;
    errno = 0;
    CHECK(mq_notify(first->queue, &event) == -1 && errno == EBUSY);
    queue_send(first->queue);
    wait_for(&first->ready);
    queue_quiet(second);
    CHECK(atomic_load(&first->calls) == 1 && atomic_load(&second->calls) == 0);
    CHECK(mq_close(first->queue) == 0);
    errno = 0;
    CHECK(mq_notify(-1, &event) == -1 && errno == EBADF);
    errno = 0;
    CHECK(mq_notify(-1, NULL) == -1 && errno == EBADF);
}

static void queue_remove(int close_descriptor) {
    struct queue_state *first = &queues[0], *second = &queues[1];
    queue_initialize(first);
    queue_initialize(second);
    mqd_t original = queue_open();
    mqd_t remaining = close_descriptor ? dup(original) : original;
    CHECK(remaining != (mqd_t)-1);
    struct sigevent event = queue_event(first, queue_callback, NULL);
    CHECK(mq_notify(original, &event) == 0);
    if (close_descriptor) CHECK(mq_close(original) == 0);
    else CHECK(mq_notify(original, NULL) == 0);
    event.sigev_value.sival_ptr = second;
    CHECK(mq_notify(remaining, &event) == 0);
    queue_send(remaining);
    wait_for(&second->ready);
    queue_quiet(first);
    CHECK(atomic_load(&first->calls) == 0 && atomic_load(&second->calls) == 1);
    CHECK(mq_close(remaining) == 0);
}

static void queue_nonempty(void) {
    struct queue_state *s = &queues[0];
    queue_initialize(s);
    s->queue = queue_open();
    queue_send(s->queue);
    struct sigevent event = queue_event(s, queue_callback, NULL);
    CHECK(mq_notify(s->queue, &event) == 0);
    queue_quiet(s);
    queue_receive(s->queue);
    queue_send(s->queue);
    wait_for(&s->ready);
    CHECK(atomic_load(&s->calls) == 1);
    CHECK(mq_close(s->queue) == 0);
}

static void queue_signal(void) {
    sigset_t mask, saved;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    CHECK(pthread_sigmask(SIG_BLOCK, &mask, &saved) == 0);
    mqd_t queue = queue_open();
    struct sigevent event = {.sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGUSR1,
                            .sigev_value.sival_int = 0x14325};
    CHECK(mq_notify(queue, &event) == 0);
    queue_send(queue);
    siginfo_t info;
    struct timespec timeout = {.tv_sec = 5};
    CHECK(sigtimedwait(&mask, &info, &timeout) == SIGUSR1);
    CHECK(info.si_code == SI_MESGQ && info.si_value.sival_int == 0x14325);
    CHECK(info.si_pid == getpid() && info.si_uid == getuid());
    CHECK(mq_close(queue) == 0);
    CHECK(pthread_sigmask(SIG_SETMASK, &saved, NULL) == 0);
}

static void queue_none(void) {
    struct queue_state *s = &queues[0];
    queue_initialize(s);
    s->queue = queue_open();
    struct sigevent event = {.sigev_notify = SIGEV_NONE};
    CHECK(mq_notify(s->queue, &event) == 0);
    event = queue_event(s, queue_callback, NULL);
    errno = 0;
    CHECK(mq_notify(s->queue, &event) == -1 && errno == EBUSY);
    queue_send(s->queue);
    CHECK(mq_notify(s->queue, &event) == 0);
    queue_receive(s->queue);
    queue_send(s->queue);
    wait_for(&s->ready);
    CHECK(atomic_load(&s->calls) == 1);
    CHECK(mq_close(s->queue) == 0);
}

static void queue_fork(int active_helper) {
    struct queue_state *parent = &queues[0], *child = &queues[1];
    queue_initialize(parent);
    parent->queue = queue_open();
    struct sigevent event = queue_event(parent, queue_callback, NULL);
    int ready[2];
    CHECK(pipe(ready) == 0);
    /* The GNU comparison forks a single-threaded process: mq_notify and
     * pthread_create are not async-signal-safe child operations after a
     * multithreaded fork. The candidate-only active-helper variant separately
     * exercises our additional recovery guarantee without treating GNU's
     * intermittent post-fork deadlock as a conformance oracle. */
    if (active_helper) CHECK(mq_notify(parent->queue, &event) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        CHECK(close(ready[1]) == 0);
        char registered;
        CHECK(read(ready[0], &registered, 1) == 1 && registered == 'R');
        CHECK(close(ready[0]) == 0);
        queue_initialize(child);
        child->queue = queue_open();
        struct sigevent own = queue_event(child, queue_callback, NULL);
        errno = 0;
        CHECK(mq_notify(parent->queue, &own) == -1 && errno == EBUSY);
        CHECK(mq_notify(child->queue, &own) == 0);
        queue_send(parent->queue);
        queue_send(child->queue);
        wait_for(&child->ready);
        CHECK(atomic_load(&child->calls) == 1 && atomic_load(&parent->calls) == 0);
        CHECK(mq_close(child->queue) == 0 && mq_close(parent->queue) == 0);
        _Exit(0);
    }
    CHECK(close(ready[0]) == 0);
    if (!active_helper) CHECK(mq_notify(parent->queue, &event) == 0);
    CHECK(write(ready[1], "R", 1) == 1);
    CHECK(close(ready[1]) == 0);
    wait_for(&parent->ready);
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(atomic_load(&parent->calls) == 1);
    CHECK(mq_close(parent->queue) == 0);
}

static void queue_cleanup(void *argument) {
    struct queue_state *s = argument;
    CHECK(sem_post(&s->cleanup) == 0);
}
static void queue_destructor(void *argument) {
    struct queue_state *s = argument;
    CHECK(sem_post(&s->finished) == 0);
}
static void queue_exit_callback(union sigval value) {
    struct queue_state *s = value.sival_ptr;
    CHECK(pthread_setspecific(s->key, s) == 0);
    pthread_cleanup_push(queue_cleanup, s);
    if (s->rearm_count) {
        CHECK(pthread_cancel(pthread_self()) == 0);
        pthread_testcancel();
        CHECK(0);
    } else {
        pthread_exit(NULL);
    }
    pthread_cleanup_pop(0);
}
static void queue_callback_exit(int cancel) {
    struct queue_state *s = &queues[0];
    queue_initialize(s);
    s->queue = queue_open();
    s->rearm_count = cancel;
    CHECK(pthread_key_create(&s->key, queue_destructor) == 0);
    struct sigevent event = queue_event(s, queue_exit_callback, NULL);
    CHECK(mq_notify(s->queue, &event) == 0);
    queue_send(s->queue);
    wait_for(&s->cleanup);
    wait_for(&s->finished);
    CHECK(mq_close(s->queue) == 0);
    CHECK(pthread_key_delete(s->key) == 0);
}

static void queue_overlap_callback(union sigval value) {
    struct queue_state *s = value.sival_ptr;
    CHECK(sem_post(&s->ready) == 0);
    wait_for(&s->release);
    CHECK(sem_post(&s->finished) == 0);
}
static void queue_overlap(void) {
    for (int i = 0; i < 2; ++i) {
        struct queue_state *s = &queues[i];
        queue_initialize(s);
        s->queue = queue_open();
        struct sigevent event = queue_event(s, queue_overlap_callback, NULL);
        CHECK(mq_notify(s->queue, &event) == 0);
        queue_send(s->queue);
        wait_for(&s->ready);
    }
    for (int i = 0; i < 2; ++i) {
        CHECK(sem_post(&queues[i].release) == 0);
        wait_for(&queues[i].finished);
        CHECK(mq_close(queues[i].queue) == 0);
    }
}

static void queue_lifetime(void) {
    struct queue_state *s = &queues[0];
    queue_initialize(s);
    s->queue = queue_open();
    struct sigevent event = queue_event(s, queue_callback, NULL);
    for (int i = 0; i < 128; ++i) {
        pthread_attr_t attr;
        CHECK(pthread_attr_init(&attr) == 0);
        CHECK(sched_getaffinity(0, sizeof(s->affinity), &s->affinity) == 0);
        CHECK(pthread_attr_setaffinity_np(&attr, sizeof(s->affinity), &s->affinity) == 0);
        event.sigev_notify_attributes = &attr;
        CHECK(mq_notify(s->queue, &event) == 0);
        CHECK(pthread_attr_destroy(&attr) == 0);
        CHECK(mq_notify(s->queue, NULL) == 0);
    }
    event.sigev_notify_attributes = NULL;
    CHECK(mq_notify(s->queue, &event) == 0);
    queue_send(s->queue);
    wait_for(&s->ready);
    CHECK(atomic_load(&s->calls) == 1);
    CHECK(mq_close(s->queue) == 0);
}

static void queue_pressure(void) {
    struct queue_state *s = &queues[0];
    queue_initialize(s);
    cpu_set_t available, single;
    CHECK(sched_getaffinity(0, sizeof(available), &available) == 0);
    CPU_ZERO(&single);
    int selected = -1;
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, &available)) { selected = cpu; break; }
    }
    CHECK(selected >= 0);
    CPU_SET(selected, &single);
    CHECK(sched_setaffinity(0, sizeof(single), &single) == 0);
    s->queue = queue_open();
    struct sigevent event = queue_event(s, queue_callback, NULL);
    /* Removal cookies can fill the helper's netlink receive buffer. Linux
     * mq_notify may then wait for receive-buffer space, so registration must
     * not hold the same registry lock that the receiver needs to keep draining.
     * One CPU exposes the registrar/receiver handoff without altering hidden
     * descriptors, socket options, or the application's queue configuration. */
    for (int i = 0; i < 200000; ++i) {
        CHECK(mq_notify(s->queue, &event) == 0);
        CHECK(mq_notify(s->queue, NULL) == 0);
    }
    CHECK(sched_setaffinity(0, sizeof(available), &available) == 0);
    CHECK(mq_notify(s->queue, &event) == 0);
    queue_send(s->queue);
    wait_for(&s->ready);
    CHECK(atomic_load(&s->calls) == 1);
    CHECK(mq_close(s->queue) == 0);
}

static void *queue_concurrent_worker(void *argument) {
    struct queue_state *s = argument;
    queue_initialize(s);
    for (int i = 0; i < 16; ++i) {
        s->queue = queue_open();
        struct sigevent event = queue_event(s, queue_callback, NULL);
        CHECK(mq_notify(s->queue, &event) == 0);
        queue_send(s->queue);
        wait_for(&s->ready);
        CHECK(atomic_load(&s->calls) == i + 1);
        CHECK(mq_close(s->queue) == 0);
    }
    return NULL;
}
static void queue_concurrent(void) {
    pthread_t workers[4];
    for (int i = 0; i < 4; ++i)
        CHECK(pthread_create(&workers[i], NULL, queue_concurrent_worker, &queues[i]) == 0);
    for (int i = 0; i < 4; ++i) CHECK(pthread_join(workers[i], NULL) == 0);
}

static int verify_provider(const char *expected) {
    static const char *symbols[] = {
        "timer_create", "timer_settime", "timer_gettime", "timer_delete", "timer_getoverrun",
        "mq_notify", "mq_open", "mq_close", "mq_send", "mq_receive", "mq_unlink",
    };
    for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); ++i) {
        void *address = dlsym(RTLD_DEFAULT, symbols[i]);
        Dl_info info;
        if (!address || !dladdr(address, &info) || !same_file(info.dli_fname, expected)) {
            fprintf(stderr, "posix-timers:provider-mismatch:%s\n", symbols[i]);
            return 86;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--provider")) {
        void *address = dlsym(RTLD_DEFAULT, "timer_create");
        Dl_info info;
        CHECK(address != NULL && dladdr(address, &info) != 0);
        puts(info.dli_fname);
        return 0;
    }
    if (argc != 4) {
        fprintf(stderr, "usage: %s CASE EXPECTED_TIMER_LIBRARY HOST_LIBC\n", argv[0]);
        return 2;
    }
    int provider = verify_provider(argv[2]);
    if (provider) return provider;
    host_library = argv[3];
    alarm(10);
    const char *name = argv[1];
    if (!strcmp(name, "thread-monotonic")) one_shot(CLOCK_MONOTONIC, 0);
    else if (!strcmp(name, "thread-realtime")) one_shot(CLOCK_REALTIME, 0);
    else if (!strcmp(name, "thread-absolute")) one_shot(CLOCK_MONOTONIC, 1);
    else if (!strcmp(name, "thread-process-cpu")) one_shot(CLOCK_PROCESS_CPUTIME_ID, 0);
    else if (!strcmp(name, "thread-thread-cpu")) one_shot(CLOCK_THREAD_CPUTIME_ID, 0);
    else if (!strcmp(name, "periodic-disarm")) periodic_disarm();
    else if (!strcmp(name, "overlap")) overlap();
    else if (!strcmp(name, "attributes-snapshot")) attributes_snapshot(0);
    else if (!strcmp(name, "foreign-attributes")) attributes_snapshot(1);
    else if (!strcmp(name, "callback-exit")) callback_exit();
    else if (!strcmp(name, "callback-cancel")) callback_cancel();
    else if (!strcmp(name, "pending-sigpipe")) pending_sigpipe();
    else if (!strcmp(name, "self-delete")) self_delete();
    else if (!strcmp(name, "signal")) raw_signal(0);
    else if (!strcmp(name, "none")) raw_none();
    else if (!strcmp(name, "default-signal")) raw_signal(1);
    else if (!strcmp(name, "fork-reset")) fork_reset();
    else if (!strcmp(name, "invalid")) invalid_requests();
    else if (!strcmp(name, "lifetime")) lifetime_cycles();
    else if (!strcmp(name, "concurrent")) concurrent_creation();
    else if (!strcmp(name, "mq-thread")) queue_thread();
    else if (!strcmp(name, "mq-attributes")) queue_attributes(0);
    else if (!strcmp(name, "mq-foreign-attributes")) queue_attributes(1);
    else if (!strcmp(name, "mq-default-attributes")) queue_defaults();
    else if (!strcmp(name, "mq-rearm")) queue_rearm();
    else if (!strcmp(name, "mq-busy")) queue_busy();
    else if (!strcmp(name, "mq-unregister")) queue_remove(0);
    else if (!strcmp(name, "mq-close")) queue_remove(1);
    else if (!strcmp(name, "mq-nonempty")) queue_nonempty();
    else if (!strcmp(name, "mq-signal")) queue_signal();
    else if (!strcmp(name, "mq-none")) queue_none();
    else if (!strcmp(name, "mq-fork")) queue_fork(0);
    else if (!strcmp(name, "mq-fork-active")) queue_fork(1);
    else if (!strcmp(name, "mq-callback-exit")) queue_callback_exit(0);
    else if (!strcmp(name, "mq-callback-cancel")) queue_callback_exit(1);
    else if (!strcmp(name, "mq-overlap")) queue_overlap();
    else if (!strcmp(name, "mq-lifetime")) queue_lifetime();
    else if (!strcmp(name, "mq-pressure")) queue_pressure();
    else if (!strcmp(name, "mq-concurrent")) queue_concurrent();
    else return 2;
    printf("posix-timers:%s:PASS\n", name);
    return 0;
}

