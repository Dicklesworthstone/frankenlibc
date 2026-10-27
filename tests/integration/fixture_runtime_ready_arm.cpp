/* Constructor arming and fresh-thread allocator/policy reentry.
 *
 * The owned runtime-policy cache allocates a Box and grows a Vec when a fresh
 * kernel TID first accesses it. Run enough distinct threads to exercise both
 * operations after the process has resolved hardened mode. A startup-only
 * probe cannot detect recursion through hardened malloc's trace context.
 *
 * Every positive workload checks its actual symbol provider. The same valid
 * allocation/string/pipe workload runs against live GNU libc. Runtime arming
 * and enabled-policy assertions apply only to candidate runs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

extern "C" {
    extern int __frankenlibc_is_runtime_ready() __attribute__((weak));
    extern int __frankenlibc_runtime_phase() __attribute__((weak));
    extern int __frankenlibc_is_runtime_math_enabled() __attribute__((weak));
}

static int g_constructor_phase = -1;
static int g_constructor_ready = -1;
static int g_constructor_allocation_ok;

// Constructors can observe either bootstrap or active, depending on loader
// ordering. main() must observe active; no constructor phase is fabricated.
class GlobalStartupObserver {
public:
    GlobalStartupObserver() {
        if (__frankenlibc_runtime_phase && __frankenlibc_is_runtime_ready) {
            g_constructor_phase = __frankenlibc_runtime_phase();
            g_constructor_ready = __frankenlibc_is_runtime_ready();
        }
    }
};

// Another constructor to test multiple constructors don't cause deadlock
class SecondGlobalObserver {
public:
    SecondGlobalObserver() {
        void* ptr = malloc(1024);
        if (!ptr) return;
        unsigned char* bytes = static_cast<unsigned char*>(ptr);
        memset(bytes, 0x42, 1024);
        g_constructor_allocation_ok = 1;
        for (size_t i = 0; i < 1024; ++i) {
            if (bytes[i] != 0x42) g_constructor_allocation_ok = 0;
        }
        free(ptr);
    }
};

// Use static instances to trigger constructors
static GlobalStartupObserver g_observer1;
static SecondGlobalObserver g_observer2;

static int same_file(const char* first, const char* second) {
    struct stat a{}, b{};
    return first && stat(first, &a) == 0 && stat(second, &b) == 0 &&
        a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static int verify_provider(const char* expected) {
    const char* names[] = {
        "malloc", "calloc", "realloc", "free", "memcpy", "memset", "memcmp",
        "strlen", "pthread_create", "pthread_join", "pipe", "read", "write",
    };
    for (const char* name : names) {
        Dl_info info{};
        void* address = dlsym(RTLD_DEFAULT, name);
        if (!address || !dladdr(address, &info) || !same_file(info.dli_fname, expected)) {
            fprintf(stderr, "runtime-ready-arm:provider-mismatch:%s\n", name);
            return 86;
        }
    }
    return 0;
}

static int runtime_ready(bool verbose) {
    if (!__frankenlibc_is_runtime_ready || !__frankenlibc_runtime_phase) {
        fprintf(stderr, "FAIL: FFI symbols not resolved (check LD_PRELOAD)\n");
        return 2;
    }
    int main_phase = __frankenlibc_runtime_phase();
    int main_ready = __frankenlibc_is_runtime_ready();
    if (verbose) {
        printf("constructor_phase=%d constructor_ready=%d main_phase=%d main_ready=%d\n",
               g_constructor_phase, g_constructor_ready, main_phase, main_ready);
        fprintf(stderr, "INFO: constructor observed phase=%d ready=%d\n",
                g_constructor_phase, g_constructor_ready);
        fprintf(stderr, "INFO: main() observes phase=%d ready=%d\n",
                main_phase, main_ready);
    }
    if (main_ready != 1 || main_phase != 2) {
        fprintf(stderr, "FAIL: runtime not ready in main() (phase=%d ready=%d)\n",
                main_phase, main_ready);
        return 1;
    }
    return 0;
}

static constexpr int ITERATIONS = 12;
static constexpr int SERIAL_THREADS = 40;
static constexpr int PARALLEL_THREADS = 48;
static constexpr int WAVE_SIZE = 12;

struct Worker {
    pthread_t thread{};
    long tid{};
    int index{};
    int wave{};
    int failure{};
};
static Worker workers[PARALLEL_THREADS];
static std::atomic<int> released_wave{0};

/* No std::thread, iostreams, exceptions, or C++ TLS in native workers: these
 * are libc contracts and must not accidentally test the host C++ runtime. */
static int exercise_memory_and_io(int seed) {
    for (int iteration = 0; iteration < ITERATIONS; ++iteration) {
        const size_t size = 128 + static_cast<size_t>((seed + iteration) % 29);
        char* first = static_cast<char*>(malloc(size));
        char* second = static_cast<char*>(calloc(size, 1));
        if (!first || !second) {
            free(first);
            free(second);
            return 1;
        }
        for (size_t i = 0; i < size; ++i) {
            if (second[i] != 0) return 2;
        }
        const int value = 'a' + (seed + iteration) % 26;
        memset(first, value, size - 1);
        first[size - 1] = 0;
        memcpy(second, first, size);
        if (strlen(first) != size - 1 || memcmp(first, second, size) != 0) return 3;
        char* grown = static_cast<char*>(realloc(first, size * 3));
        if (!grown) {
            free(first);
            free(second);
            return 4;
        }
        if (memcmp(grown, second, size) != 0) return 5;
        memset(grown + size, value + 1, size * 2);
        for (size_t i = size; i < size * 3; ++i) {
            if (grown[i] != value + 1) return 6;
        }

        int fd[2];
        if (pipe(fd) != 0) return 7;
        char message = static_cast<char>(value), received = 0;
        if (write(fd[1], &message, 1) != 1 || read(fd[0], &received, 1) != 1 ||
            received != message) return 8;
        if (close(fd[0]) != 0 || close(fd[1]) != 0) return 9;
        free(grown);
        free(second);
    }
    return 0;
}

static void* fresh_worker(void* argument) {
    Worker* worker = static_cast<Worker*>(argument);
    worker->tid = syscall(SYS_gettid);
    while (released_wave.load(std::memory_order_acquire) < worker->wave) {
        std::atomic_signal_fence(std::memory_order_seq_cst);
    }
    // Start with a policy-bearing syscall, before malloc can initialize this
    // thread's runtime cache under its own allocator recursion guard.
    char byte;
    if (read(-1, &byte, 1) != -1 || errno != EBADF) {
        worker->failure = 10;
        return worker;
    }
    worker->failure = exercise_memory_and_io(worker->index + 1);
    return worker;
}

static int fresh_threads(bool parallel) {
    const int count = parallel ? PARALLEL_THREADS : SERIAL_THREADS;
    const int width = parallel ? WAVE_SIZE : 1;
    for (int offset = 0; offset < count; offset += width) {
        const int wave = offset / width + 1;
        for (int i = offset; i < offset + width; ++i) {
            workers[i].index = i;
            workers[i].wave = wave;
            int rc = pthread_create(&workers[i].thread, nullptr, fresh_worker, &workers[i]);
            if (rc) {
                fprintf(stderr, "runtime-ready-arm:create:%d:%d\n", i, rc);
                return 1;
            }
        }
        released_wave.store(wave, std::memory_order_release);
        // Keep ordinary application allocation/policy calls live while new
        // threads initialize their independent runtime-policy cache entries.
        if (parallel && exercise_memory_and_io(offset + count)) return 1;
        for (int i = offset; i < offset + width; ++i) {
            void* result = nullptr;
            int rc = pthread_join(workers[i].thread, &result);
            if (rc || result != &workers[i] || workers[i].failure) {
                fprintf(stderr, "runtime-ready-arm:join:%d:%d:%d\n",
                        i, rc, workers[i].failure);
                return 1;
            }
            if (workers[i].tid <= 0) return 1;
            for (int j = 0; j < i; ++j) {
                if (workers[i].tid == workers[j].tid) {
                    fprintf(stderr, "runtime-ready-arm:kernel-tid-reused:%d:%d\n", i, j);
                    return 1;
                }
            }
        }
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 2 && strcmp(argv[1], "--provider") == 0) {
        Dl_info info{};
        if (!dladdr(dlsym(RTLD_DEFAULT, "malloc"), &info)) return 1;
        puts(info.dli_fname);
        return 0;
    }
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "-v") == 0)) {
        int rc = runtime_ready(argc == 2);
        if (rc) return rc;
        if (!g_constructor_allocation_ok) return 1;
        puts("PASS: runtime armed by main()");
        return 0;
    }
    if ((argc != 4 && argc != 5) || strcmp(argv[1], "--case") != 0) return 2;
    const bool reference = argc == 5 && strcmp(argv[4], "--reference") == 0;
    if (argc == 5 && !reference) return 2;
    int rc = verify_provider(argv[3]);
    if (rc) return rc;
    if (!g_constructor_allocation_ok) return 1;
    if (!reference) {
        if ((rc = runtime_ready(false)) != 0) return rc;
        if (!__frankenlibc_is_runtime_math_enabled ||
            __frankenlibc_is_runtime_math_enabled() != 1) return 1;
    }
    const char* name = argv[2];
    int count = 0;
    if (strcmp(name, "startup") == 0) {
        rc = exercise_memory_and_io(0);
    } else if (strcmp(name, "fresh-serial") == 0) {
        count = SERIAL_THREADS;
        rc = fresh_threads(false);
    } else if (strcmp(name, "fresh-parallel") == 0) {
        count = PARALLEL_THREADS;
        rc = fresh_threads(true);
    } else {
        return 2;
    }
    if (rc) return rc;
    if (!reference && runtime_ready(false)) return 1;
    printf("runtime-ready-arm:%s:PASS workers=%d iterations=%d\n", name, count, ITERATIONS);
    return 0;
}
