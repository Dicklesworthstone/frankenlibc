// Real C++ exceptions must cross the exported pthread_once implementation.
// Run without preload for the glibc oracle, then with the candidate library
// preloaded and its absolute path as argv[1] to verify symbol ownership.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <mutex>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

using OnceFn = int (*)(pthread_once_t *, void (*)());
static OnceFn once_fn;

[[noreturn]] static void fail(const char *message) {
    std::fprintf(stderr, "FAIL: %s\n", message);
    std::fflush(stderr);
    _Exit(1);
}

static void require(bool condition, const char *message) {
    if (!condition) {
        fail(message);
    }
}

struct InitFailure {
    unsigned attempt;
};

struct CallbackCleanup {
    std::atomic<unsigned> &count;
    ~CallbackCleanup() { count.fetch_add(1, std::memory_order_relaxed); }
};

static pthread_once_t retry_once = PTHREAD_ONCE_INIT;
static unsigned retry_attempts;
static std::atomic<unsigned> retry_cleanups{0};
static int retry_value;

static void retry_init() {
    CallbackCleanup cleanup{retry_cleanups};
    const unsigned attempt = ++retry_attempts;
    if (attempt <= 3) {
        throw InitFailure{attempt};
    }
    retry_value = 0x513;
}

static void must_not_run() { fail("a completed once invoked its initializer again"); }

static void sequential_retry() {
    for (unsigned attempt = 1; attempt <= 3; ++attempt) {
        bool caught = false;
        try {
            (void)once_fn(&retry_once, retry_init);
        } catch (const InitFailure &failure) {
            require(failure.attempt == attempt, "exception payload changed");
            caught = true;
        } catch (...) {
            fail("unexpected exception type");
        }
        require(caught, "pthread_once swallowed the initializer exception");
        require(retry_cleanups.load() == attempt, "callback destructor did not run");
    }
    require(once_fn(&retry_once, retry_init) == 0, "successful retry failed");
    require(retry_attempts == 4 && retry_value == 0x513, "retry did not initialize");
    require(retry_cleanups.load() == 4, "successful callback was not cleaned up");
    for (unsigned i = 0; i != 32; ++i) {
        require(once_fn(&retry_once, must_not_run) == 0, "completed fast path failed");
    }
    std::puts("PASS sequential-retry");
}

static pthread_once_t inner_once = PTHREAD_ONCE_INIT;
static pthread_once_t outer_once = PTHREAD_ONCE_INIT;
static unsigned inner_attempts;
static unsigned outer_attempts;
static std::atomic<unsigned> nested_cleanups{0};
static int nested_value;

static void inner_init() {
    CallbackCleanup cleanup{nested_cleanups};
    if (++inner_attempts == 1) {
        throw InitFailure{71};
    }
    nested_value = 17;
}

static void outer_init() {
    CallbackCleanup cleanup{nested_cleanups};
    ++outer_attempts;
    require(once_fn(&inner_once, inner_init) == 0, "inner retry failed");
    nested_value += 25;
}

static void nested_retry() {
    bool caught = false;
    try {
        (void)once_fn(&outer_once, outer_init);
    } catch (const InitFailure &failure) {
        require(failure.attempt == 71, "nested exception payload changed");
        caught = true;
    }
    require(caught, "nested once swallowed the exception");
    require(nested_cleanups.load() == 2, "nested callback cleanup missing");
    require(once_fn(&outer_once, outer_init) == 0, "outer retry failed");
    require(inner_attempts == 2 && outer_attempts == 2, "nested once was not reset");
    require(nested_value == 42 && nested_cleanups.load() == 4, "nested publication failed");
    require(once_fn(&outer_once, must_not_run) == 0, "outer completion missing");
    require(once_fn(&inner_once, must_not_run) == 0, "inner completion missing");
    std::puts("PASS nested-retry");
}

static pthread_once_t caught_once = PTHREAD_ONCE_INIT;
static unsigned caught_attempts;

static void caught_init() {
    ++caught_attempts;
    try {
        throw InitFailure{19};
    } catch (const InitFailure &) {
        // The initializer completed normally. Internal exceptions must not
        // cause pthread_once to reset an otherwise successful initialization.
    }
}

static void caught_in_initializer() {
    require(once_fn(&caught_once, caught_init) == 0, "internally caught exception failed");
    require(once_fn(&caught_once, must_not_run) == 0, "internal catch reset the once");
    require(caught_attempts == 1, "internally caught initializer repeated");
    std::puts("PASS caught-in-initializer");
}

static void standard_call_once() {
    std::once_flag flag;
    unsigned attempts = 0;
    int value = 0;
    auto initialize = [&] {
        if (++attempts == 1) {
            throw InitFailure{23};
        }
        value = 91;
    };
    bool caught = false;
    try {
        std::call_once(flag, initialize);
    } catch (const InitFailure &failure) {
        require(failure.attempt == 23, "std::call_once payload changed");
        caught = true;
    }
    require(caught, "std::call_once swallowed the exception");
    std::call_once(flag, initialize);
    std::call_once(flag, must_not_run);
    require(attempts == 2 && value == 91, "std::call_once retry failed");
    std::puts("PASS std-call-once");
}

struct ContendedRound {
    pthread_once_t once = PTHREAD_ONCE_INIT;
    std::atomic<unsigned> attempts{0};
    std::atomic<unsigned> cleanups{0};
    std::atomic<unsigned> ready{0};
    std::atomic<unsigned> successful_waiters{0};
    std::atomic<bool> entered{false};
    std::atomic<bool> release{false};
    std::atomic<bool> caught{false};
    int published_value = 0;
};

// Written before thread creation, changed only after all threads are joined.
static ContendedRound *current_round;

static void contended_init() {
    auto &round = *current_round;
    CallbackCleanup cleanup{round.cleanups};
    if (round.attempts.fetch_add(1, std::memory_order_relaxed) == 0) {
        round.entered.store(true, std::memory_order_release);
        while (!round.release.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        throw InitFailure{101};
    }
    // Deliberately non-atomic: pthread_once's release/acquire publication,
    // rather than an unrelated atomic value, must make this visible.
    round.published_value = 0x1357;
}

static void contended_retry() {
    constexpr unsigned rounds = 16;
    constexpr unsigned waiter_count = 8;
    for (unsigned trial = 0; trial != rounds; ++trial) {
        ContendedRound round;
        current_round = &round;
        std::thread owner([&] {
            try {
                (void)once_fn(&round.once, contended_init);
                fail("contended owner did not receive its exception");
            } catch (const InitFailure &failure) {
                require(failure.attempt == 101, "contended payload changed");
                round.caught.store(true, std::memory_order_release);
            }
            // Do not retry here: progress must come from waking a waiter.
        });
        while (!round.entered.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        std::vector<std::thread> waiters;
        waiters.reserve(waiter_count);
        for (unsigned i = 0; i != waiter_count; ++i) {
            waiters.emplace_back([&] {
                round.ready.fetch_add(1, std::memory_order_release);
                require(once_fn(&round.once, contended_init) == 0, "waiter retry failed");
                require(round.published_value == 0x1357, "initializer writes not published");
                round.successful_waiters.fetch_add(1, std::memory_order_relaxed);
            });
        }
        while (round.ready.load(std::memory_order_acquire) != waiter_count) {
            std::this_thread::yield();
        }
        // Encourage the FUTEX_WAIT path rather than testing only CAS races.
        // The outer timeout makes a missing wake a failure, never a skip.
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        round.release.store(true, std::memory_order_release);
        owner.join();
        for (auto &waiter : waiters) {
            waiter.join();
        }
        require(round.caught.load(), "owner exception did not reach its caller");
        require(round.attempts.load() == 2, "contended initializer executed too often");
        require(round.cleanups.load() == 2, "contended callback cleanup missing");
        require(round.successful_waiters.load() == waiter_count, "waiters were stranded");
        require(once_fn(&round.once, must_not_run) == 0, "contended completion missing");
    }
    std::puts("PASS contended-retry: 16 rounds, 8 waiters per round");
}

// Fork tests use pthreads directly so the same scenarios can select the owned
// clone backend without relying on libstdc++ thread-local exception machinery
// in those workers. Only the forking/main thread throws a C++ exception.
static pid_t (*fork_fn)();
static std::uintptr_t creator_tp;
static bool native_backend;
static pid_t parent_pid;
static pthread_once_t fork_once = PTHREAD_ONCE_INIT;
static std::atomic<unsigned> fork_attempts{0}, fork_cleanups{0};
static std::atomic<int> owner_tid{0}, waiter_tid{0}, owner_release{0}, waiter_done{0};
static bool child_retry;
static int child_handler_calls;
static int fork_value;

static void verify_worker_backend() {
    require((reinterpret_cast<std::uintptr_t>(__builtin_thread_pointer()) == creator_tp) ==
                native_backend,
            "thread backend does not match hosted/native request");
}

static void orphan_init() {
    CallbackCleanup cleanup{fork_cleanups};
    const unsigned attempt = fork_attempts.fetch_add(1, std::memory_order_relaxed) + 1;
    if (static_cast<pid_t>(syscall(SYS_getpid)) == parent_pid) {
        while (owner_release.load(std::memory_order_acquire) == 0) {
            (void)syscall(SYS_futex, &owner_release, FUTEX_WAIT_PRIVATE, 0,
                          nullptr, nullptr, 0);
        }
    } else if (child_retry && attempt == 2) {
        throw InitFailure{129};
    }
    fork_value = 0x3157;
}

static void *fork_owner(void *) {
    verify_worker_backend();
    owner_tid.store(static_cast<int>(syscall(SYS_gettid)), std::memory_order_release);
    require(once_fn(&fork_once, orphan_init) == 0, "parent owner failed");
    return nullptr;
}

static void *fork_waiter(void *) {
    verify_worker_backend();
    waiter_tid.store(static_cast<int>(syscall(SYS_gettid)), std::memory_order_release);
    require(once_fn(&fork_once, orphan_init) == 0, "parent waiter failed");
    require(fork_value == 0x3157, "parent waiter did not acquire publication");
    waiter_done.store(1, std::memory_order_release);
    return nullptr;
}

static bool proc_text(int tid, const char *leaf, char *text, std::size_t capacity) {
    char path[128];
    std::snprintf(path, sizeof(path), "/proc/self/task/%d/%s", tid, leaf);
    const int fd = static_cast<int>(syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0));
    if (fd < 0) return false;
    const long count = syscall(SYS_read, fd, text, capacity - 1);
    (void)syscall(SYS_close, fd);
    if (count <= 0) return false;
    text[count] = 0;
    return true;
}

static void observe_futex(const std::atomic<int> &tid, const void *word) {
    // A published "entered" flag is insufficient: require an independent
    // kernel snapshot of the precise futex and a sleeping task before forking.
    for (unsigned attempt = 0; attempt != 2000; ++attempt) {
        const int worker = tid.load(std::memory_order_acquire);
        char call[512], status[512];
        long number = -1;
        unsigned long long address = 0;
        if (worker > 0 && proc_text(worker, "syscall", call, sizeof(call)) &&
            std::sscanf(call, "%ld %llx", &number, &address) == 2 &&
            number == SYS_futex && address == reinterpret_cast<std::uintptr_t>(word) &&
            proc_text(worker, "stat", status, sizeof(status))) {
            const char *tail = std::strrchr(status, ')');
            if (tail != nullptr && tail[1] == ' ' && tail[2] == 'S') return;
        }
        const timespec delay{0, 1000000};
        (void)syscall(SYS_nanosleep, &delay, nullptr);
    }
    fail("initializer or waiter was not observed sleeping on its expected futex");
}

[[noreturn]] static void child_success() {
    (void)syscall(SYS_exit_group, 0);
    __builtin_unreachable();
}

static void wait_child(pid_t child) {
    int status = -1;
    require(waitpid(child, &status, 0) == child, "waitpid failed");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "fork child failed or inherited a stranded once initializer");
}

static void child_once_handler() {
    alarm(2);
    require(once_fn(&fork_once, orphan_init) == 0, "child handler could not acquire once");
    ++child_handler_calls;
}

static void fork_orphan(const char *test_name, bool in_handler, bool retry) {
    child_retry = retry;
    if (in_handler)
        require(pthread_atfork(nullptr, nullptr, child_once_handler) == 0, "register child once handler");
    pthread_t owner{}, waiter{};
    require(pthread_create(&owner, nullptr, fork_owner, nullptr) == 0, "create once owner");
    observe_futex(owner_tid, &owner_release);
    require(pthread_create(&waiter, nullptr, fork_waiter, nullptr) == 0, "create once waiter");
    observe_futex(waiter_tid, &fork_once);
    // Independent siblings must both recover, while the parent's owner and
    // waiter retain their original generation and execute the callback once.
    for (unsigned sibling = 0; sibling != 2; ++sibling) {
        const pid_t child = fork_fn();
        require(child >= 0, "fork orphaned initializer");
        if (child == 0) {
            alarm(2);
            if (retry) {
                bool caught = false;
                try {
                    (void)once_fn(&fork_once, orphan_init);
                } catch (const InitFailure &failure) {
                    require(failure.attempt == 129, "child initializer exception changed");
                    caught = true;
                }
                require(caught, "child initializer did not propagate its exception");
            }
            require(once_fn(&fork_once, orphan_init) == 0, "child once retry failed");
            require(once_fn(&fork_once, must_not_run) == 0, "child once completion was lost");
            require(fork_attempts.load() == (retry ? 3u : 2u) && fork_value == 0x3157,
                    "child initialized the wrong number of times");
            require(fork_cleanups.load() == (retry ? 2u : 1u), "child initializer cleanup missing");
            require(child_handler_calls == (in_handler ? 1 : 0), "child handler execution mismatch");
            child_success();
        }
        wait_child(child);
        require(waiter_done.load(std::memory_order_acquire) == 0 && fork_attempts.load() == 1,
                "child recovery changed the parent's in-progress initialization");
    }
    owner_release.store(1, std::memory_order_release);
    (void)syscall(SYS_futex, &owner_release, FUTEX_WAKE_PRIVATE, 1, nullptr, nullptr, 0);
    require(pthread_join(owner, nullptr) == 0 && pthread_join(waiter, nullptr) == 0,
            "join parent once owner and waiter");
    require(fork_attempts.load() == 1 && fork_cleanups.load() == 1 && waiter_done.load() == 1,
            "parent once ownership or waiter wake changed across fork");
    require(once_fn(&fork_once, must_not_run) == 0, "parent once completion was lost");
    std::printf("PASS %s\n", test_name);
}

static pthread_once_t survivor_once = PTHREAD_ONCE_INIT;
static unsigned survivor_attempts;
static pid_t survivor_child;
static bool survivor_throws;
static int survivor_value;

static void survivor_retry_init() {
    ++survivor_attempts;
    survivor_value = 81;
}

static void survivor_init() {
    ++survivor_attempts;
    survivor_child = fork_fn();
    require(survivor_child >= 0, "fork from initializer");
    if (survivor_child == 0 && survivor_throws) throw InitFailure{171};
    survivor_value = 81;
}

static void fork_survivor(bool throws) {
    survivor_throws = throws;
    bool caught = false;
    try {
        require(once_fn(&survivor_once, survivor_init) == 0, "surviving initializer failed");
    } catch (const InitFailure &failure) {
        require(survivor_child == 0 && throws && failure.attempt == 171,
                "surviving initializer exception reached the wrong process");
        caught = true;
    }
    if (survivor_child == 0) {
        alarm(2);
        require(caught == throws, "surviving child's exception state changed");
        require(once_fn(&survivor_once, throws ? survivor_retry_init : must_not_run) == 0,
                "surviving child's once retry failed");
        require(survivor_attempts == (throws ? 2u : 1u) && survivor_value == 81,
                "surviving child lost initialization");
        require(once_fn(&survivor_once, must_not_run) == 0, "surviving child lost DONE");
        child_success();
    }
    wait_child(survivor_child);
    require(!caught && survivor_attempts == 1 && survivor_value == 81,
            "fork changed the parent's surviving initializer");
    require(once_fn(&survivor_once, must_not_run) == 0, "surviving parent lost DONE");
    std::puts(throws ? "PASS fork-survivor-retry" : "PASS fork-survivor");
}

static void fork_completed() {
    require(once_fn(&survivor_once, survivor_retry_init) == 0, "initialize before fork");
    const pid_t child = fork_fn();
    require(child >= 0, "fork completed initializer");
    if (child == 0) {
        alarm(2);
        require(once_fn(&survivor_once, must_not_run) == 0 && survivor_attempts == 1 &&
                    survivor_value == 81,
                "fork reran a completed initializer");
        child_success();
    }
    wait_child(child);
    require(once_fn(&survivor_once, must_not_run) == 0, "parent lost pre-fork DONE");
    std::puts("PASS fork-completed");
}

static pthread_once_t cancel_once = PTHREAD_ONCE_INIT;
static std::atomic<unsigned> cancel_attempts{0}, cancel_cleanups{0};
static std::atomic<bool> cancel_entered{false}, cancel_release{false};
static int cancel_value;

static void cancel_init() {
    CallbackCleanup cleanup{cancel_cleanups};
    if (cancel_attempts.fetch_add(1, std::memory_order_relaxed) == 0) {
        cancel_entered.store(true, std::memory_order_release);
        while (!cancel_release.load(std::memory_order_acquire)) (void)syscall(SYS_sched_yield);
        pthread_testcancel();
        fail("pending cancellation did not leave the initializer");
    }
    cancel_value = 97;
}

static void *cancel_owner(void *) {
    verify_worker_backend();
    (void)once_fn(&cancel_once, cancel_init);
    fail("canceled once owner returned");
}

static void canceled_retry() {
    pthread_t owner{};
    require(pthread_create(&owner, nullptr, cancel_owner, nullptr) == 0, "create canceled initializer");
    while (!cancel_entered.load(std::memory_order_acquire)) (void)syscall(SYS_sched_yield);
    require(pthread_cancel(owner) == 0, "cancel once owner");
    cancel_release.store(true, std::memory_order_release);
    void *result = nullptr;
    require(pthread_join(owner, &result) == 0 && result == PTHREAD_CANCELED,
            "once owner did not join as canceled");
    require(cancel_cleanups.load() == 1, "canceled initializer destructor did not run");
    require(once_fn(&cancel_once, cancel_init) == 0 && cancel_attempts.load() == 2 &&
                cancel_cleanups.load() == 2 && cancel_value == 97,
            "cancellation did not reset once for a successful retry");
    require(once_fn(&cancel_once, must_not_run) == 0, "canceled retry lost DONE");
    std::puts("PASS canceled-retry");
}

static void verify_provider(const char *symbol, const char *expected_path) {
    void *address = dlsym(RTLD_DEFAULT, symbol);
    Dl_info info{};
    struct stat expected{}, actual{};
    require(address != nullptr && dladdr(address, &info) != 0 && info.dli_fname != nullptr &&
                stat(expected_path, &expected) == 0 && stat(info.dli_fname, &actual) == 0 &&
                expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino,
            "fork/once fixture symbol provider mismatch");
}

int main(int argc, char **argv) {
    require(argc <= 3, "usage: fixture_pthread_once_unwind [expected-library] [--case]");
    alarm(20);
    void *symbol = dlsym(RTLD_DEFAULT, "pthread_once");
    require(symbol != nullptr, "pthread_once symbol missing");
    once_fn = reinterpret_cast<OnceFn>(symbol);
    const char *expected_path = argc >= 2 && std::strncmp(argv[1], "--", 2) != 0 ? argv[1] : nullptr;
    const char *test_case = argc == 3 ? argv[2] : argc == 2 && expected_path == nullptr ? argv[1] : nullptr;
    if (expected_path != nullptr) {
        Dl_info info{};
        struct stat expected{}, actual{};
        require(dladdr(symbol, &info) != 0 && info.dli_fname != nullptr,
                "cannot establish pthread_once symbol ownership");
        require(stat(expected_path, &expected) == 0 && stat(info.dli_fname, &actual) == 0,
                "cannot stat expected/actual pthread_once library");
        require(expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino,
                "pthread_once did not bind to the candidate library");
    }
    if (test_case != nullptr) {
        Dl_info provider{};
        require(dladdr(symbol, &provider) != 0 && provider.dli_fname != nullptr, "once provider path");
        const char *wanted = expected_path != nullptr ? expected_path : provider.dli_fname;
        // GNU pthread_atfork is a nonshared wrapper whose external binding is
        // __register_atfork; pin that provider rather than require a default-
        // version pthread_atfork symbol that GNU does not export.
        for (const char *required : {"pthread_create", "pthread_join", "pthread_cancel", "pthread_testcancel", "fork", "__register_atfork"})
            verify_provider(required, wanted);
        fork_fn = reinterpret_cast<decltype(fork_fn)>(dlsym(RTLD_DEFAULT, "fork"));
        const char *backend = std::getenv("FRANKENLIBC_THREAD_NATIVE");
        native_backend = backend != nullptr && std::strcmp(backend, "1") == 0;
        creator_tp = reinterpret_cast<std::uintptr_t>(__builtin_thread_pointer());
        parent_pid = static_cast<pid_t>(syscall(SYS_getpid));
        if (std::strcmp(test_case, "--fork-orphan") == 0) fork_orphan("fork-orphan", false, false);
        else if (std::strcmp(test_case, "--fork-child-handler") == 0) fork_orphan("fork-child-handler", true, false);
        else if (std::strcmp(test_case, "--fork-retry") == 0) fork_orphan("fork-retry", false, true);
        else if (std::strcmp(test_case, "--fork-survivor") == 0) fork_survivor(false);
        else if (std::strcmp(test_case, "--fork-survivor-retry") == 0) fork_survivor(true);
        else if (std::strcmp(test_case, "--fork-completed") == 0) fork_completed();
        else if (std::strcmp(test_case, "--canceled-retry") == 0) canceled_retry();
        else fail("unknown once fixture case");
        alarm(0);
        return 0;
    }
    sequential_retry();
    nested_retry();
    caught_in_initializer();
    standard_call_once();
    contended_retry();
    alarm(0);
    return 0;
}
