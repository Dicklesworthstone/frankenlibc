#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cxxabi.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sched.h>
#include <sys/stat.h>
#include <threads.h>
#include <time.h>
#include <unistd.h>

/* C++ destructors and a forced-unwind catch/rethrow must survive both the
 * thrd_create adapter and the exit/sleep wrappers, not just C cleanup macros. */
static std::atomic<int> ready{0};
static std::atomic<int> destroyed{0};
static std::atomic<int> caught{0};

static void check(bool ok, const char *what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        std::exit(1);
    }
}

struct Guard {
    ~Guard() { destroyed.fetch_add(1, std::memory_order_relaxed); }
};

extern "C" int cpp_worker(void *arg) {
    const char *kind = static_cast<const char *>(arg);
    try {
        Guard guard;
        if (std::strcmp(kind, "cpp-exit") == 0)
            thrd_exit(42);
        if (std::strcmp(kind, "cpp-cancel") == 0) {
            const timespec delay{30, 0};
            ready.store(1, std::memory_order_release);
            (void)thrd_sleep(&delay, nullptr);
            check(false, "canceled C++ sleeper must not return");
        }
        return 42;
    } catch (const __cxxabiv1::__forced_unwind &) {
        caught.fetch_add(1, std::memory_order_relaxed);
        throw;
    }
}

static void check_provider(void *symbol) {
    const char *library = std::getenv("FRANKENLIBC_TEST_LIBRARY");
    if (!library)
        return;
    Dl_info origin;
    struct stat actual, expected;
    check(dladdr(symbol, &origin) != 0, "locate C11 provider");
    check(stat(origin.dli_fname, &actual) == 0 && stat(library, &expected) == 0,
          "stat C11 provider");
    check(actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino,
          "C11 symbol must bind to candidate");
}

int main(int argc, char **argv) {
    check(argc == 2, "one case name required");
    const bool cancel = std::strcmp(argv[1], "cpp-cancel") == 0;
    const bool exiting = std::strcmp(argv[1], "cpp-exit") == 0;
    check(cancel || exiting || std::strcmp(argv[1], "cpp-return") == 0, "known case");
    alarm(8);
    check_provider(reinterpret_cast<void *>(thrd_create));
    check_provider(reinterpret_cast<void *>(thrd_join));
    check_provider(reinterpret_cast<void *>(thrd_exit));
    check_provider(reinterpret_cast<void *>(thrd_sleep));
    thrd_t thread;
    check(thrd_create(&thread, cpp_worker, argv[1]) == thrd_success, "create C++ C11 worker");
    if (cancel) {
        while (!ready.load(std::memory_order_acquire))
            sched_yield();
        const timespec delay{0, 5000000};
        (void)nanosleep(&delay, nullptr);
        check(pthread_cancel(static_cast<pthread_t>(thread)) == 0, "cancel C++ C11 worker");
    }
    int result = 0;
    check(thrd_join(thread, &result) == thrd_success, "join C++ C11 worker");
    check(result == (cancel ? -1 : 42), "C++ C11 result");
    check(destroyed.load() == 1, "C++ destructor must run exactly once");
    check(caught.load() == (cancel || exiting ? 1 : 0), "forced unwind must be catchable and rethrown");
    alarm(0);
    std::printf("PASS %s\n", argv[1]);
    return 0;
}
