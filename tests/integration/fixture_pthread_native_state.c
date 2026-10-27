#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "pthread-native-state:%s:%d: %s (errno=%d)\n", \
                __func__, __LINE__, #expression, errno); \
        _Exit(1); \
    } \
} while (0)

/* Each case has its own process. Shared objects outlive every callback and
 * signal handler; publication uses atomics or the pthread_join boundary. */
struct worker {
    pthread_t thread;
    pid_t tid;
    int *slot;
    int marker;
    int initial_state;
    int initial_type;
    int state;
    int type;
    int before_error;
    int after_error;
    int destructor_ok;
    int disabled_survived;
    int after_cancel;
    _Atomic int command;
    _Atomic int stage;
    _Atomic int signals;
    _Atomic int signal_error;
    _Atomic int destructors;
};
static struct worker workers[2];
static pthread_key_t key;
static int *parent_slot;
static int explicit_exit;

static void wait_at_least(_Atomic int *word, int value) {
    while (atomic_load_explicit(word, memory_order_acquire) < value) {}
}

static void publish(_Atomic int *word, int value) {
    atomic_store_explicit(word, value, memory_order_release);
}

static int same_file(const char *first, const char *second) {
    struct stat a, b;
    return stat(first, &a) == 0 && stat(second, &b) == 0 &&
        a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static int verify_provider(const char *expected) {
    static const char *names[] = {
        "__errno_location", "pthread_create", "pthread_join", "pthread_exit",
        "pthread_setcancelstate", "pthread_setcanceltype", "pthread_testcancel",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        void *address = dlsym(RTLD_DEFAULT, names[i]);
        Dl_info info;
        if (!address || !dladdr(address, &info) || !same_file(info.dli_fname, expected)) {
            fprintf(stderr, "pthread-native-state:provider-mismatch:%s\n", names[i]);
            return 86;
        }
    }
    return 0;
}

static void prepare(void) {
    parent_slot = __errno_location();
    for (int i = 0; i < 2; ++i) workers[i].marker = 601 + i;
}

static void *errno_worker(void *argument) {
    struct worker *w = argument;
    w->tid = gettid();
    w->slot = __errno_location();
    publish(&w->stage, 1);
    wait_at_least(&w->command, 1);
    errno = w->marker;
    publish(&w->stage, 2);
    wait_at_least(&w->command, 2);
    w->before_error = errno;
    char byte;
    CHECK(read(-1, &byte, 1) == -1);
    w->after_error = errno;
    publish(&w->stage, 3);
    wait_at_least(&w->command, 3);
    return w;
}

static void errno_siblings(void) {
    prepare();
    for (int i = 0; i < 2; ++i) {
        CHECK(pthread_create(&workers[i].thread, NULL, errno_worker, &workers[i]) == 0);
        wait_at_least(&workers[i].stage, 1);
    }
    errno = 603;
    /* Deliberately order the writes: corruption in the old implementation is
     * deterministic, without racing plain int stores to the shared old slot. */
    for (int i = 0; i < 2; ++i) {
        publish(&workers[i].command, 1);
        wait_at_least(&workers[i].stage, 2);
    }
    CHECK(workers[0].slot != parent_slot && workers[1].slot != parent_slot);
    CHECK(workers[0].slot != workers[1].slot && errno == 603);
    for (int i = 0; i < 2; ++i) {
        publish(&workers[i].command, 2);
        wait_at_least(&workers[i].stage, 3);
        CHECK(workers[i].before_error == workers[i].marker);
        CHECK(workers[i].after_error == EBADF && errno == 603);
    }
    for (int i = 0; i < 2; ++i) {
        void *result = NULL;
        publish(&workers[i].command, 3);
        CHECK(pthread_join(workers[i].thread, &result) == 0 && result == &workers[i]);
    }
    CHECK(errno == 603);
}

static void signal_handler(int signal) {
    (void)signal;
    _Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal bookkeeping must be lock-free");
    pid_t tid = gettid();
    for (int i = 0; i < 2; ++i) {
        struct worker *w = &workers[i];
        if (w->tid != tid) continue;
        int saved = errno;
        int bad = saved != w->marker || __errno_location() != w->slot || w->slot == parent_slot;
        errno = 710 + i;
        if (errno != 710 + i) bad = 1;
        errno = saved;
        if (bad) atomic_store_explicit(&w->signal_error, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&w->signals, 1, memory_order_release);
        return;
    }
    _Exit(91);
}

static void install_signal_handler(void) {
    struct sigaction action = {.sa_handler = signal_handler};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    sigset_t unblocked;
    sigemptyset(&unblocked);
    sigaddset(&unblocked, SIGUSR1);
    CHECK(pthread_sigmask(SIG_UNBLOCK, &unblocked, NULL) == 0);
}

static void errno_signals(void) {
    prepare();
    install_signal_handler();
    for (int i = 0; i < 2; ++i) {
        CHECK(pthread_create(&workers[i].thread, NULL, errno_worker, &workers[i]) == 0);
        wait_at_least(&workers[i].stage, 1);
        publish(&workers[i].command, 1);
        wait_at_least(&workers[i].stage, 2);
    }
    errno = 603;
    for (int i = 0; i < 2; ++i) {
        CHECK(pthread_kill(workers[i].thread, SIGUSR1) == 0);
        wait_at_least(&workers[i].signals, 1);
        CHECK(!atomic_load(&workers[i].signal_error) && errno == 603);
    }
    for (int i = 0; i < 2; ++i) {
        publish(&workers[i].command, 2);
        wait_at_least(&workers[i].stage, 3);
        CHECK(workers[i].before_error == workers[i].marker);
        publish(&workers[i].command, 3);
        CHECK(pthread_join(workers[i].thread, NULL) == 0);
    }
    CHECK(errno == 603);
}

static void errno_destructor(void *argument) {
    struct worker *w = argument;
    int observed = errno;
    sigset_t mask;
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0);
    w->destructor_ok = __errno_location() == w->slot && w->slot != parent_slot &&
        observed == w->marker && sigismember(&mask, SIGUSR1) == 0;
    CHECK(raise(SIGUSR1) == 0);
    char byte;
    CHECK(read(-1, &byte, 1) == -1);
    w->after_error = errno;
    atomic_fetch_add_explicit(&w->destructors, 1, memory_order_release);
}

static void *lifecycle_worker(void *argument) {
    struct worker *w = argument;
    w->tid = gettid();
    w->slot = __errno_location();
    CHECK(pthread_setspecific(key, w) == 0);
    publish(&w->stage, 1);
    wait_at_least(&w->command, 1);
    errno = w->marker;
    if (explicit_exit) pthread_exit(w);
    return w;
}

static void errno_lifecycle(int exit_call) {
    prepare();
    install_signal_handler();
    explicit_exit = exit_call;
    CHECK(pthread_key_create(&key, errno_destructor) == 0);
    struct worker *w = &workers[0];
    CHECK(pthread_create(&w->thread, NULL, lifecycle_worker, w) == 0);
    wait_at_least(&w->stage, 1);
    errno = 603;
    publish(&w->command, 1);
    void *result = NULL;
    CHECK(pthread_join(w->thread, &result) == 0 && result == w);
    CHECK(w->destructor_ok && atomic_load(&w->destructors) == 1);
    CHECK(atomic_load(&w->signals) == 1 && !atomic_load(&w->signal_error));
    CHECK(w->after_error == EBADF && errno == 603);
    CHECK(pthread_key_delete(key) == 0);
}

static void *settings_worker(void *argument) {
    struct worker *w = argument;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &w->initial_state) == 0);
    CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &w->initial_type) == 0);
    publish(&w->stage, 1);
    wait_at_least(&w->command, 1);
    CHECK(pthread_setcancelstate(w->state, NULL) == 0);
    CHECK(pthread_setcanceltype(w->type, NULL) == 0);
    publish(&w->stage, 2);
    wait_at_least(&w->command, 2);
    int state, type;
    CHECK(pthread_setcancelstate(w->state, &state) == 0 && state == w->state);
    CHECK(pthread_setcanceltype(w->type, &type) == 0 && type == w->type);
    return w;
}

static void cancel_settings(int repeat) {
    int original_state, original_type;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &original_state) == 0);
    CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &original_type) == 0);
    for (int round = 0; round < (repeat ? 24 : 1); ++round) {
        for (int i = 0; i < 2; ++i) {
            struct worker *w = &workers[i];
            atomic_store(&w->stage, 0);
            atomic_store(&w->command, 0);
            w->state = i ? PTHREAD_CANCEL_ENABLE : PTHREAD_CANCEL_DISABLE;
            w->type = i ? PTHREAD_CANCEL_DEFERRED : PTHREAD_CANCEL_ASYNCHRONOUS;
            CHECK(pthread_create(&w->thread, NULL, settings_worker, w) == 0);
            wait_at_least(&w->stage, 1);
            CHECK(w->initial_state == PTHREAD_CANCEL_ENABLE);
            CHECK(w->initial_type == PTHREAD_CANCEL_DEFERRED);
        }
        for (int i = 0; i < 2; ++i) {
            publish(&workers[i].command, 1);
            wait_at_least(&workers[i].stage, 2);
        }
        int state, type;
        CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state) == 0);
        CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &type) == 0);
        CHECK(state == PTHREAD_CANCEL_DISABLE && type == PTHREAD_CANCEL_ASYNCHRONOUS);
        for (int i = 0; i < 2; ++i) {
            publish(&workers[i].command, 2);
            CHECK(pthread_join(workers[i].thread, NULL) == 0);
        }
    }
    CHECK(pthread_setcanceltype(original_type, NULL) == 0);
    CHECK(pthread_setcancelstate(original_state, NULL) == 0);
}

static void *invalid_worker(void *unused) {
    (void)unused;
    int value = 777;
    errno = 603;
    CHECK(pthread_setcancelstate(-1, &value) == EINVAL && value == 777);
    CHECK(pthread_setcanceltype(-1, &value) == EINVAL && value == 777);
    CHECK(errno == 603);
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &value) == 0);
    CHECK(value == PTHREAD_CANCEL_ENABLE);
    CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &value) == 0);
    CHECK(value == PTHREAD_CANCEL_DEFERRED);
    return NULL;
}

static void cancel_invalid(void) {
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, invalid_worker, NULL) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
}

static void *leave_pending_worker(void *argument) {
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    CHECK(pthread_cancel(pthread_self()) == 0);
    if (argument) pthread_exit((void *)(uintptr_t)0x111);
    return (void *)(uintptr_t)0x111;
}

static void *fresh_cancel_worker(void *unused) {
    (void)unused;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0);
    pthread_testcancel();
    return (void *)(uintptr_t)0x222;
}

static void cancel_pending_reuse(void) {
    for (int round = 0; round < 64; ++round) {
        pthread_t thread;
        void *result = NULL;
        CHECK(pthread_create(&thread, NULL, leave_pending_worker,
                             (void *)(uintptr_t)(round & 1)) == 0);
        CHECK(pthread_join(thread, &result) == 0);
        CHECK(result == (void *)(uintptr_t)0x111);
        CHECK(pthread_create(&thread, NULL, fresh_cancel_worker, NULL) == 0);
        CHECK(pthread_join(thread, &result) == 0);
        CHECK(result == (void *)(uintptr_t)0x222);
    }
}

static void cancel_destructor(void *argument) {
    struct worker *w = argument;
    w->destructor_ok = __errno_location() == w->slot && w->slot != parent_slot;
    atomic_fetch_add_explicit(&w->destructors, 1, memory_order_release);
}

static void *cooperative_worker(void *argument) {
    struct worker *w = argument;
    w->slot = __errno_location();
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    CHECK(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL) == 0);
    CHECK(pthread_setspecific(key, w) == 0);
    publish(&w->stage, 1);
    wait_at_least(&w->command, 1);
    pthread_testcancel();
    w->disabled_survived = 1;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0);
    pthread_testcancel();
    w->after_cancel = 1;
    return NULL;
}

static void cooperative_cancel(void) {
    prepare();
    CHECK(pthread_key_create(&key, cancel_destructor) == 0);
    int original_state, original_type;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &original_state) == 0);
    CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &original_type) == 0);
    struct worker *w = &workers[0];
    CHECK(pthread_create(&w->thread, NULL, cooperative_worker, w) == 0);
    wait_at_least(&w->stage, 1);
    CHECK(pthread_cancel(w->thread) == 0);
    publish(&w->command, 1);
    void *result = NULL;
    CHECK(pthread_join(w->thread, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(w->disabled_survived && !w->after_cancel && w->destructor_ok);
    CHECK(atomic_load(&w->destructors) == 1);
    int state, type;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state) == 0);
    CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &type) == 0);
    CHECK(state == PTHREAD_CANCEL_DISABLE && type == PTHREAD_CANCEL_ASYNCHRONOUS);
    CHECK(pthread_key_delete(key) == 0);
    CHECK(pthread_setcanceltype(original_type, NULL) == 0);
    CHECK(pthread_setcancelstate(original_state, NULL) == 0);
}

struct cleanup_state {
    pthread_t thread;
    int cancel;
    int reenter;
    int log[12];
    int count;
    _Atomic int ready;
    _Atomic int release;
};

struct cleanup_argument {
    struct cleanup_state *state;
    int marker;
};

static struct cleanup_state cleanup_states[2];
static _Atomic int initial_cleanup_done;

static void record_cleanup(void *argument) {
    struct cleanup_argument *entry = argument;
    struct cleanup_state *state = entry->state;
    CHECK(state->count < (int)(sizeof(state->log) / sizeof(state->log[0])));
    state->log[state->count++] = entry->marker;
    CHECK(pthread_getspecific(key) == state);
    if (state->reenter == 1 && entry->marker == 2) {
        struct cleanup_argument nested = {state, 4};
        pthread_cleanup_push(record_cleanup, &nested);
        pthread_cleanup_pop(1);
    } else if (state->reenter == 2 && entry->marker == 2) {
        /* An exit already in progress is not restarted by a pending request
         * at a cancellation point in application cleanup code. */
        CHECK(pthread_cancel(pthread_self()) == 0);
        CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) == 0);
        pthread_testcancel();
        state->log[state->count++] = 4;
    }
}

static void cleanup_key_destructor(void *argument) {
    struct cleanup_state *state = argument;
    CHECK(pthread_getspecific(key) == NULL);
    if (state->reenter == 3) {
        CHECK(pthread_cancel(pthread_self()) == 0);
        CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) == 0);
        pthread_testcancel();
    }
    CHECK(state->count < (int)(sizeof(state->log) / sizeof(state->log[0])));
    state->log[state->count++] = 9;
    if (state->reenter == 4) publish(&initial_cleanup_done, 1);
}

static void *cleanup_worker(void *argument) {
    struct cleanup_state *state = argument;
    struct cleanup_argument first = {state, 1};
    struct cleanup_argument second = {state, 2};
    struct cleanup_argument popped = {state, 3};
    CHECK(pthread_setspecific(key, state) == 0);
    pthread_cleanup_push(record_cleanup, &first);
    pthread_cleanup_push(record_cleanup, &popped);
    pthread_cleanup_pop(0);
    pthread_cleanup_push(record_cleanup, &second);
    publish(&state->ready, 1);
    wait_at_least(&state->release, 1);
    if (state->cancel) {
        pthread_testcancel();
        _Exit(92);
    }
    if (state->reenter != 3) pthread_exit(state);
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    return state;
}

static void cleanup_exit(int cancel, int reenter, int siblings) {
    CHECK(pthread_key_create(&key, cleanup_key_destructor) == 0);
    int count = siblings ? 2 : 1;
    for (int i = 0; i < count; ++i) {
        struct cleanup_state *state = &cleanup_states[i];
        state->cancel = cancel;
        state->reenter = reenter;
        CHECK(pthread_create(&state->thread, NULL, cleanup_worker, state) == 0);
        wait_at_least(&state->ready, 1);
    }
    for (int i = 0; i < count; ++i) {
        struct cleanup_state *state = &cleanup_states[i];
        if (cancel) CHECK(pthread_cancel(state->thread) == 0);
        publish(&state->release, 1);
        void *result = NULL;
        CHECK(pthread_join(state->thread, &result) == 0);
        if (reenter == 3) {
            /* GNU permits a new cancellation to interrupt a key destructor
             * entered after an ordinary start-routine return. Explicit exit
             * has already entered its unwind protocol and suppresses restart. */
            CHECK(result == PTHREAD_CANCELED && state->count == 0);
            continue;
        }
        CHECK(result == (cancel ? PTHREAD_CANCELED : (void *)state));
        CHECK(state->count == (reenter ? 4 : 3));
        CHECK(state->log[0] == 2);
        if (reenter) CHECK(state->log[1] == 4);
        CHECK(state->log[state->count - 2] == 1);
        CHECK(state->log[state->count - 1] == 9);
        if (i + 1 < count) CHECK(cleanup_states[i + 1].count == 0);
    }
    CHECK(pthread_key_delete(key) == 0);
}

static void *cleanup_defer_worker(void *argument) {
    struct cleanup_state *state = argument;
    struct cleanup_argument first = {state, 1};
    struct cleanup_argument second = {state, 2};
    CHECK(pthread_setspecific(key, state) == 0);
    CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) == 0);
    pthread_cleanup_push(record_cleanup, &first);
    pthread_cleanup_push_defer_np(record_cleanup, &second);
    int type;
    CHECK(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &type) == 0);
    CHECK(type == PTHREAD_CANCEL_DEFERRED);
    publish(&state->ready, 1);
    wait_at_least(&state->release, 1);
    /* GNU's C setjmp macro unregisters before restoring ASYNCHRONOUS. With
     * -fexceptions the language cleanup frame remains live across the restore.
     * Both header-selected contracts are checked below against live GNU. */
    pthread_cleanup_pop_restore_np(0);
    _Exit(93);
    pthread_cleanup_pop(0);
    return NULL;
}

static void cleanup_defer(void) {
    CHECK(pthread_key_create(&key, cleanup_key_destructor) == 0);
    struct cleanup_state *state = &cleanup_states[0];
    CHECK(pthread_create(&state->thread, NULL, cleanup_defer_worker, state) == 0);
    wait_at_least(&state->ready, 1);
    CHECK(pthread_cancel(state->thread) == 0);
    publish(&state->release, 1);
    void *result = NULL;
    CHECK(pthread_join(state->thread, &result) == 0 && result == PTHREAD_CANCELED);
#ifdef __EXCEPTIONS
    CHECK(state->count == 3 && state->log[0] == 2 && state->log[1] == 1 && state->log[2] == 9);
#else
    CHECK(state->count == 2 && state->log[0] == 1 && state->log[1] == 9);
#endif
    CHECK(pthread_key_delete(key) == 0);
}

static void *observe_initial_cleanup(void *argument) {
    struct cleanup_state *state = argument;
    wait_at_least(&initial_cleanup_done, 1);
    CHECK(state->count == 3 && state->log[0] == 2 && state->log[1] == 1 && state->log[2] == 9);
    puts("pthread-native-state:cleanup-initial:PASS");
    fflush(stdout);
    _Exit(0);
}

static void cleanup_initial(void) {
    CHECK(pthread_key_create(&key, cleanup_key_destructor) == 0);
    struct cleanup_state *state = &cleanup_states[0];
    state->reenter = 4;
    CHECK(pthread_setspecific(key, state) == 0);
    CHECK(pthread_create(&state->thread, NULL, observe_initial_cleanup, state) == 0);
    struct cleanup_argument first = {state, 1};
    struct cleanup_argument second = {state, 2};
    pthread_cleanup_push(record_cleanup, &first);
    pthread_cleanup_push(record_cleanup, &second);
    pthread_exit(state);
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
}

/* Linked into the C++ native-unwind probe as an independently compiled C
 * frame without exception landing pads. Its registered cleanup must run
 * between the inner and outer C++ destructors, in the same unwind. */
void frankenlibc_native_cleanup_frame(void (*callback)(void *),
                                     void (*cleanup)(void *), void *argument) {
    pthread_cleanup_push(cleanup, argument);
    callback(argument);
    pthread_cleanup_pop(0);
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--provider")) {
        Dl_info info;
        CHECK(dladdr(dlsym(RTLD_DEFAULT, "__errno_location"), &info) != 0);
        puts(info.dli_fname);
        return 0;
    }
    if (argc != 3) return 2;
    int provider = verify_provider(argv[2]);
    if (provider) return provider;
    alarm(12);
    const char *name = argv[1];
    if (!strcmp(name, "errno-siblings")) errno_siblings();
    else if (!strcmp(name, "errno-signals")) errno_signals();
    else if (!strcmp(name, "errno-return")) errno_lifecycle(0);
    else if (!strcmp(name, "errno-exit")) errno_lifecycle(1);
    else if (!strcmp(name, "cancel-settings")) cancel_settings(0);
    else if (!strcmp(name, "cancel-reuse")) cancel_settings(1);
    else if (!strcmp(name, "cancel-invalid")) cancel_invalid();
    else if (!strcmp(name, "cancel-pending-reuse")) cancel_pending_reuse();
    else if (!strcmp(name, "cooperative-cancel")) cooperative_cancel();
    else if (!strcmp(name, "cleanup-exit")) cleanup_exit(0, 0, 0);
    else if (!strcmp(name, "cleanup-cancel")) cleanup_exit(1, 0, 0);
    else if (!strcmp(name, "cleanup-reentry")) cleanup_exit(0, 1, 0);
    else if (!strcmp(name, "cleanup-cancel-reentry")) cleanup_exit(1, 2, 0);
    else if (!strcmp(name, "cleanup-siblings")) cleanup_exit(1, 1, 1);
    else if (!strcmp(name, "cleanup-defer")) cleanup_defer();
    else if (!strcmp(name, "cleanup-initial")) cleanup_initial();
    else if (!strcmp(name, "cleanup-return-reentry")) cleanup_exit(0, 3, 0);
    else return 2;
    printf("pthread-native-state:%s:PASS\n", name);
    return 0;
}
