// Real C++ exceptions must cross the exported pthread_once implementation.
// Run without preload for the glibc oracle, then with the candidate library
// preloaded and its absolute path as argv[1] to verify symbol ownership.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <mutex>
#include <pthread.h>
#include <sys/stat.h>
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

int main(int argc, char **argv) {
    require(argc <= 2, "usage: fixture_pthread_once_unwind [expected-library]");
    alarm(20);
    void *symbol = dlsym(RTLD_DEFAULT, "pthread_once");
    require(symbol != nullptr, "pthread_once symbol missing");
    once_fn = reinterpret_cast<OnceFn>(symbol);
    if (argc == 2) {
        Dl_info info{};
        struct stat expected{}, actual{};
        require(dladdr(symbol, &info) != 0 && info.dli_fname != nullptr,
                "cannot establish pthread_once symbol ownership");
        require(stat(argv[1], &expected) == 0 && stat(info.dli_fname, &actual) == 0,
                "cannot stat expected/actual pthread_once library");
        require(expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino,
                "pthread_once did not bind to the candidate library");
    }
    sequential_retry();
    nested_retry();
    caught_in_initializer();
    standard_call_once();
    contended_retry();
    alarm(0);
    return 0;
}
