#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <aio.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cxxabi.h>
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

// Foreign callbacks may reap/free their aiocb, exit, or be canceled. None of
// these may abort at a Rust ABI boundary or swallow a C++ forced unwind.
static std::atomic<int> destroyed{0};
static std::atomic<int> caught{0};
static std::atomic<int> completed{0};
static const char data[] = "aio-cxx-cleanup";

static void check(bool ok, const char *what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        std::_Exit(1);
    }
}

struct Request { aiocb cb; char buffer[sizeof(data)]; int mode; };
struct Guard {
    ~Guard() { destroyed.fetch_add(1, std::memory_order_release); }
};

static void finished(void *) {
    completed.fetch_add(1, std::memory_order_release);
}

extern "C" void callback(union sigval value) {
    Request *request = static_cast<Request *>(value.sival_ptr);
    check(aio_error(&request->cb) == 0, "callback status published");
    check(aio_return(&request->cb) == static_cast<ssize_t>(sizeof(data)), "callback return published");
    check(std::memcmp(request->buffer, data, sizeof(data)) == 0, "callback buffer published");
    const int mode = request->mode;
    delete request;
    pthread_cleanup_push(finished, nullptr);
    try {
        Guard guard;
        if (mode == 1) pthread_exit(nullptr);
        if (mode == 2) {
            check(pthread_cancel(pthread_self()) == 0, "queue callback cancellation");
            pthread_testcancel();
            check(false, "canceled callback must not return");
        }
    } catch (const __cxxabiv1::__forced_unwind &) {
        caught.fetch_add(1, std::memory_order_release);
        throw;
    }
    pthread_cleanup_pop(1);
}

static void provider(void *symbol) {
    const char *library = std::getenv("FRANKENLIBC_TEST_LIBRARY");
    if (!library) return;
    Dl_info info;
    struct stat actual, expected;
    check(dladdr(symbol, &info) != 0, "resolve AIO provider");
    check(stat(info.dli_fname, &actual) == 0 && stat(library, &expected) == 0, "stat AIO provider");
    check(actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino, "candidate AIO provider");
}

int main(int argc, char **argv) {
    check(argc == 2, "one case required");
    const int mode = std::strcmp(argv[1], "cpp-exit") == 0 ? 1 :
                     std::strcmp(argv[1], "cpp-cancel") == 0 ? 2 : 0;
    check(mode || std::strcmp(argv[1], "cpp-return") == 0, "known case");
    alarm(8);
    provider(reinterpret_cast<void *>(aio_read));
    provider(reinterpret_cast<void *>(aio_error));
    provider(reinterpret_cast<void *>(aio_return));
    int pipes[2];
    check(pipe(pipes) == 0, "create callback pipe");
    Request *request = new Request{};
    request->mode = mode;
    request->cb.aio_fildes = pipes[0];
    request->cb.aio_buf = request->buffer;
    request->cb.aio_nbytes = sizeof(data);
    request->cb.aio_sigevent.sigev_notify = SIGEV_THREAD;
    request->cb.aio_sigevent.sigev_notify_function = callback;
    request->cb.aio_sigevent.sigev_value.sival_ptr = request;
    check(aio_read(&request->cb) == 0, "submit C++ callback");
    check(write(pipes[1], data, sizeof(data)) == static_cast<ssize_t>(sizeof(data)), "complete callback I/O");
    while (!completed.load(std::memory_order_acquire)) {
        const timespec delay{0, 1000000};
        (void)nanosleep(&delay, nullptr);
    }
    check(destroyed.load() == 1 && completed.load() == 1, "C++ destructor and cleanup execute once");
    check(caught.load() == (mode ? 1 : 0), "forced unwind is catchable and rethrown");
    alarm(0);
    std::printf("PASS %s\n", argv[1]);
}
