// Exercise the real C++ TLS ABI in separate, bounded processes. No runtime shim.
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <netdb.h>
#include <pthread.h>
#include <sched.h>
#include <sys/stat.h>
#include <unistd.h>

extern "C" int __cxa_thread_atexit_impl(void (*)(void *), void *, void *);
using Exit = void (*)(int);
static Exit terminate_process = std::exit;
static std::atomic<int> destroyed{0};
static std::atomic<int> ready{0};
static std::atomic<int> release_worker{0};
static int expected_destroyed;
static bool use_runtime;

#define CHECK(x) do { if (!(x)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); std::_Exit(111); \
} } while (0)

static void emit(char c) { CHECK(write(STDOUT_FILENO, &c, 1) == 1); }
[[noreturn]] static void finish(int status) { terminate_process(status); std::_Exit(112); }
static void late_exit() { emit('L'); }
static void touch_new_tls();

struct Object {
    char label;
    int action;
    Object(char c, int a = 0) : label(c), action(a) {}
    ~Object() {
        emit(label);
        destroyed.fetch_add(1, std::memory_order_relaxed);
        if (action == 1) CHECK(std::atexit(late_exit) == 0);
        if (action == 2) touch_new_tls();
        if (action == 3) finish(37);
    }
};
static void touch_a() { thread_local Object value('A'); (void)value; }
static void touch_b(int action = 0) { thread_local Object value('B', action); (void)value; }
static void touch_main() { thread_local Object value('M'); (void)value; }
static void touch_other() { thread_local Object value('W'); (void)value; }
static void touch_new_tls() { thread_local Object value('N'); (void)value; }

static void process_callback() {
    CHECK(destroyed.load(std::memory_order_relaxed) == expected_destroyed);
    if (use_runtime) {
        // A host TLS drain also destroys Rust TLS slots. Exit callbacks still
        // need working allocation, stdio, locks and numeric name resolution.
        char *p = static_cast<char *>(std::malloc(128));
        CHECK(p != nullptr);
        CHECK(std::snprintf(p, 128, "%s:%d", "alive", 42) == 8);
        CHECK(std::strcmp(p, "alive:42") == 0);
        char *end = nullptr;
        CHECK(std::strtol(p + 6, &end, 10) == 42 && *end == '\0');
        std::free(p);
        pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
        CHECK(pthread_mutex_lock(&mutex) == 0);
        CHECK(pthread_mutex_unlock(&mutex) == 0);
        CHECK(pthread_mutex_destroy(&mutex) == 0);
        addrinfo hint{}, *result = nullptr;
        hint.ai_family = AF_INET;
        hint.ai_socktype = SOCK_STREAM;
        hint.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
        CHECK(getaddrinfo("127.0.0.1", "80", &hint, &result) == 0 && result != nullptr);
        freeaddrinfo(result);
        FILE *file = tmpfile();
        CHECK(file != nullptr && std::fputs("after TLS", file) >= 0);
        CHECK(std::fflush(file) == 0 && std::fseek(file, 0, SEEK_SET) == 0);
        char data[16]{};
        CHECK(std::fread(data, 1, 9, file) == 9 && std::strcmp(data, "after TLS") == 0);
        CHECK(std::fclose(file) == 0);
    }
    emit('E');
}
static void key_destructor(void *) { emit('K'); }
static void quick_callback() { emit('Q'); }

static void *worker_exit(void *) { touch_a(); touch_b(); finish(23); }
static void *worker_return(void *) { touch_a(); touch_b(); return nullptr; }
static void *worker_wait(void *) {
    touch_other();
    ready.store(1, std::memory_order_release);
    while (!release_worker.load(std::memory_order_acquire)) sched_yield();
    return nullptr;
}

static void require_provider(void *symbol) {
    const char *path = std::getenv("FRANKENLIBC_TEST_LIBRARY");
    if (!path) return;
    Dl_info info{};
    struct stat actual{}, expected{};
    CHECK(dladdr(symbol, &info) != 0 && stat(info.dli_fname, &actual) == 0 && stat(path, &expected) == 0);
    if (actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino) {
        std::fputs("WRONG EXIT/TLS PROVIDER\n", stderr);
        std::_Exit(113);
    }
}

int main(int argc, char **argv) {
    CHECK(argc == 2);
    require_provider(reinterpret_cast<void *>(std::exit));
    require_provider(reinterpret_cast<void *>(__cxa_thread_atexit_impl));
    const char *provider = std::getenv("TEST_EXIT_PROVIDER");
    if (provider && !std::strcmp(provider, "host")) {
        void *host = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
        CHECK(host != nullptr);
        terminate_process = reinterpret_cast<Exit>(dlsym(host, "exit"));
        CHECK(terminate_process != nullptr);
    }
    const char *kind = argv[1];
    if (!std::strcmp(kind, "empty")) {
        expected_destroyed = 0;
        CHECK(std::atexit(process_callback) == 0);
        finish(23);
    }
    expected_destroyed = !std::strcmp(kind, "new-tls") ? 3 : 2;
    use_runtime = !std::strcmp(kind, "runtime-after-tls");
    CHECK(std::atexit(process_callback) == 0);
    if (!std::strcmp(kind, "worker-exit")) {
        touch_main(); // Exiting worker must NOT destroy the main thread's TLS.
        pthread_t thread;
        CHECK(pthread_create(&thread, nullptr, worker_exit, nullptr) == 0);
        CHECK(pthread_join(thread, nullptr) == 0);
        CHECK(false);
    }
    if (!std::strcmp(kind, "worker-return")) {
        pthread_t thread;
        CHECK(pthread_create(&thread, nullptr, worker_return, nullptr) == 0);
        CHECK(pthread_join(thread, nullptr) == 0);
        // Already-drained worker objects must not be visited by process exit.
        finish(23);
    }
    if (!std::strcmp(kind, "other-thread")) {
        pthread_t thread;
        CHECK(pthread_create(&thread, nullptr, worker_wait, nullptr) == 0);
        while (!ready.load(std::memory_order_acquire)) sched_yield();
        // The other thread touches no runtime after publishing readiness except
        // sched_yield. Its TLS must remain outside this thread's exit drain.
    }
    if (!std::strcmp(kind, "pthread-key")) {
        pthread_key_t key;
        CHECK(pthread_key_create(&key, key_destructor) == 0);
        CHECK(pthread_setspecific(key, reinterpret_cast<void *>(1)) == 0);
    }
    touch_a();
    touch_b(!std::strcmp(kind, "new-atexit") ? 1 : !std::strcmp(kind, "new-tls") ? 2 :
            !std::strcmp(kind, "recursive") ? 3 : 0);
    if (!std::strcmp(kind, "immediate")) std::_Exit(23);
    if (!std::strcmp(kind, "quick")) {
        CHECK(std::at_quick_exit(quick_callback) == 0);
        std::quick_exit(23);
    }
    if (!std::strcmp(kind, "return-main")) return 23;
    CHECK(!std::strcmp(kind, "explicit") || !std::strcmp(kind, "new-atexit") ||
          !std::strcmp(kind, "new-tls") || !std::strcmp(kind, "recursive") ||
          !std::strcmp(kind, "other-thread") || !std::strcmp(kind, "pthread-key") || use_runtime);
    finish(23);
}
