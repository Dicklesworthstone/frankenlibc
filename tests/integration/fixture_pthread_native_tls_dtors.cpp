// Public C++ TLS destructor registration belongs to the calling native thread,
// even though that clone currently inherits its creator's hardware TLS.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <atomic>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

extern "C" int __cxa_thread_atexit_impl(void (*)(void *), void *, void *);
extern "C" int __cxa_atexit(void (*)(void *), void *, void *);
extern "C" void __cxa_finalize(void *);
extern "C" void *__dso_handle;

using Destructor = void (*)(void *);
using Emit = void (*)(int, void *);

#ifdef FRANKENLIBC_TLS_DTOR_MODULE

#ifdef FRANKENLIBC_TLS_DTOR_NATIVE_MODULE
extern "C" {
__attribute__((visibility("hidden"))) void *__dso_handle = &__dso_handle;
}
#endif
static Emit module_emit;
static void *module_argument;
static void module_destructor(void *) { module_emit(7, module_argument); }
extern "C" Destructor tls_fixture_callback(void) { return module_destructor; }
extern "C" void *tls_fixture_owner(void) { return __dso_handle; }
extern "C" void *tls_fixture_registration_provider(void) {
    return (void *)__cxa_thread_atexit_impl;
}
extern "C" void tls_fixture_prepare(Emit emit, void *argument) {
    module_emit = emit;
    module_argument = argument;
}
__attribute__((destructor)) static void module_finalize(void) {
    if (module_emit) module_emit(8, module_argument);
}

#else

static std::atomic<int> ready(0);
static std::atomic<int> release_worker(0);
static std::atomic<int> event_count(0);
static std::atomic<int> wrong_thread(0);
static std::atomic<int> registration_failed(0);
static std::atomic<int> creator_callbacks(0);
static std::atomic<int> module_registration(99);
static long worker_tid;
static long creator_tid;
static uintptr_t worker_tp;
static uintptr_t creator_tp;
static int events[16];
static const char *exit_kind;
static const char *thread_exit_kind;
static bool compiler_tls_case;
static pthread_key_t late_key;
static bool use_late_key;
static Destructor module_callback;
static void *module_owner;
static void *module_argument;
static int runtime_owner_token;
static bool process_exit_case;
static bool recursive_process_exit;
static bool empty_process_exit;
static bool expected_native_backend;
static char process_tokens[] = "alpha,beta,gamma,delta";
static char *process_address;

static bool process_scratch_matches(const char *expected_token) {
    if (!process_address || strcmp(process_address, "203.0.113.7"))
        return false;
    char *token = strtok(nullptr, ",");
    return token && !strcmp(token, expected_token);
}

static void check_provider(const char *symbol) {
    const char *expected = getenv("FRANKENLIBC_TEST_LIBRARY");
    if (!expected) return;
    void *address = dlsym(RTLD_DEFAULT, symbol);
    Dl_info info;
    struct stat actual, wanted;
    if (!address || !dladdr(address, &info) || !info.dli_fname ||
        stat(info.dli_fname, &actual) || stat(expected, &wanted) ||
        actual.st_dev != wanted.st_dev || actual.st_ino != wanted.st_ino) {
        fprintf(stderr, "wrong provider for %s\n", symbol);
        _exit(80);
    }
}

static void record(void *argument) {
    if (syscall(SYS_gettid) != worker_tid) wrong_thread.store(1);
    int value = (int)(uintptr_t)argument;
    int index = event_count.fetch_add(1);
    if (index < 16) events[index] = value;
    if (process_exit_case &&
        !process_scratch_matches(value == 2 ? "beta" : value == 3 ? "gamma" : "delta"))
        registration_failed.store(1);
    if (value == 2 &&
        __cxa_thread_atexit_impl(record, (void *)(uintptr_t)3, &__dso_handle))
        registration_failed.store(1);
    if (value == 2 && recursive_process_exit) exit(0);
}

// Only the worker touches these objects. Its compiler-generated registrations
// must enter its native queue even though its hardware TLS aliases the creator.
struct ProcessTlsWitness {
    int value;
    explicit ProcessTlsWitness(int number) : value(number) {}
    ~ProcessTlsWitness() { record((void *)(uintptr_t)value); }
};

static void touch_process_tls() {
    thread_local ProcessTlsWitness first(1);
    thread_local ProcessTlsWitness second(2);
    (void)first;
    (void)second;
}

static void process_exit_check() {
    // Process callbacks must still be able to use libc after the TLS drain.
    // Request fresh scratch here: host teardown may have retired old buffers.
    in_addr address{htonl(0xcb007108U)};
    char *current_address = inet_ntoa(address);
    char tokens[] = "process,callback";
    char *first = strtok(tokens, ",");
    char *second = strtok(nullptr, ",");
    bool scratch_ok = current_address && !strcmp(current_address, "203.0.113.8") &&
                      first && !strcmp(first, "process") &&
                      second && !strcmp(second, "callback");
    bool ok = syscall(SYS_gettid) == worker_tid && worker_tid != creator_tid &&
              ((worker_tp == creator_tp) == expected_native_backend) &&
              !registration_failed.load() && !wrong_thread.load() &&
              !creator_callbacks.load() &&
              event_count.load() == (empty_process_exit ? 0 : 3) &&
              (empty_process_exit || (events[0] == 2 && events[1] == 3 && events[2] == 1)) &&
              scratch_ok;
    printf("native public TLS dtors %s: events=%d [%d,%d,%d] creator=%d "
           "wrong_thread=%d registration_failed=%d %s\n", exit_kind,
           event_count.load(), events[0], events[1], events[2],
           creator_callbacks.load(), wrong_thread.load(), registration_failed.load(),
           ok ? "PASS" : "FAIL");
    fflush(stdout);
    if (!ok) _exit(43);
}

static void creator_callback(void *) {
    if (syscall(SYS_gettid) != creator_tid) _exit(81);
    creator_callbacks.fetch_add(1);
}

static void late_key_callback(void *) {
    record((void *)(uintptr_t)4);
    if (__cxa_thread_atexit_impl(record, (void *)(uintptr_t)5, &__dso_handle))
        registration_failed.store(1);
}

static void module_event(int value, void *) {
    if (value == 7 && syscall(SYS_gettid) != worker_tid) wrong_thread.store(1);
    int index = event_count.fetch_add(1);
    if (index < 16) events[index] = value;
}

static void *worker(void *) {
    worker_tid = syscall(SYS_gettid);
    worker_tp = (uintptr_t)__builtin_thread_pointer();
    if (module_callback) {
        module_registration.store(
            __cxa_thread_atexit_impl(module_callback, module_argument, module_owner));
        ready.store(1, std::memory_order_release);
        while (!release_worker.load(std::memory_order_acquire)) sched_yield();
        return (void *)(uintptr_t)17;
    }
    if (use_late_key && pthread_setspecific(late_key, (void *)(uintptr_t)1))
        registration_failed.store(1);
    if (process_exit_case) {
        if (!empty_process_exit) {
            // These buffers must survive every C++ TLS callback.
            in_addr address{htonl(0xcb007107U)};
            process_address = inet_ntoa(address);
            char *first = strtok(process_tokens, ",");
            if (!process_address || !first || strcmp(first, "alpha"))
                registration_failed.store(1);
            touch_process_tls();
        }
    } else if (compiler_tls_case) {
        touch_process_tls();
    } else if (__cxa_thread_atexit_impl(record, (void *)(uintptr_t)1, &__dso_handle) ||
               __cxa_thread_atexit_impl(record, (void *)(uintptr_t)2, &__dso_handle)) {
        registration_failed.store(1);
    }
    ready.store(1, std::memory_order_release);
    if (process_exit_case) exit(0);
    if (strcmp(thread_exit_kind, "cancel") == 0) {
        for (;;) {
            pthread_testcancel();
            sched_yield();
        }
    }
    if (strcmp(thread_exit_kind, "exit") == 0) pthread_exit((void *)(uintptr_t)17);
    return (void *)(uintptr_t)17;
}

static bool prepare_runtime_pin_retry(bool consumed, bool native) {
    // Save the complete error text before exercising the first native create.
    // A second identical failure lets both pending and already-returned error
    // cases compare the original message without relying on locale wording.
    const char *missing = "/proc/self/fd/-1";
    char expected_error[512];
    (void)dlerror();
    if (dlopen(missing, RTLD_NOW)) return false;
    const char *sample = dlerror();
    if (!sample || !strstr(sample, missing) ||
        strlen(sample) >= sizeof(expected_error))
        return false;
    memcpy(expected_error, sample, strlen(sample) + 1);
    if (dlerror() != nullptr) return false;

    if (dlopen(missing, RTLD_NOW)) return false;
    const char *retained = consumed ? dlerror() : nullptr;
    if (consumed && (!retained || strcmp(retained, expected_error)))
        return false;

    // This first worker uses executable callbacks, which remain valid even
    // when retaining the creator's error prevents a runtime-image pin.
    errno = EDOM;
    pthread_t first;
    int created = pthread_create(&first, nullptr, worker, nullptr);
    bool errno_preserved = errno == EDOM;
    if (created) return false;
    void *result = nullptr;
    if (pthread_join(first, &result)) return false;
    if (!retained) retained = dlerror();
    bool ok = errno_preserved && retained &&
              strcmp(retained, expected_error) == 0 &&
              result == (void *)(uintptr_t)17 &&
              !registration_failed.load() && !wrong_thread.load() &&
              !creator_callbacks.load() && event_count.load() == 3 &&
              events[0] == 2 && events[1] == 3 && events[2] == 1 &&
              worker_tid != creator_tid &&
              ((worker_tp == creator_tp) == native);
    if (!ok) return false;

    // A normal successful lookup is followed by an explicit public dlerror
    // call. That next dlerror call retires the borrowed message even when it
    // returns NULL, allowing the following native create to retry the pin.
    // Do not dereference the previous error pointer after this lookup.
    if (!dlsym(RTLD_DEFAULT, "__cxa_finalize") || dlerror() != nullptr)
        return false;

    ready.store(0);
    release_worker.store(0);
    event_count.store(0);
    memset(events, 0, sizeof(events));
    return true;
}

int main(int argc, char **argv) {
    exit_kind = argc >= 2 ? argv[1] : "return";
    compiler_tls_case = !strcmp(exit_kind, "compiler-return") ||
                        !strcmp(exit_kind, "compiler-exit") ||
                        !strcmp(exit_kind, "compiler-cancel");
    thread_exit_kind = compiler_tls_case ? exit_kind + strlen("compiler-") : exit_kind;
    bool native_module = !strcmp(exit_kind, "native-dso");
    bool host_owner = !strcmp(exit_kind, "host-owner");
    bool host_provider = !strcmp(exit_kind, "host-provider");
    bool use_module = native_module || host_owner || host_provider;
    bool runtime_retry = !strcmp(exit_kind, "runtime-retry-pending") ||
                         !strcmp(exit_kind, "runtime-retry-consumed");
    bool runtime_callback = !strcmp(exit_kind, "runtime-callback") || runtime_retry;
    recursive_process_exit = !strcmp(exit_kind, "process-recursive");
    empty_process_exit = !strcmp(exit_kind, "process-empty");
    process_exit_case = !strcmp(exit_kind, "process-exit") ||
                        recursive_process_exit || empty_process_exit;
    const char *native_setting = getenv("FRANKENLIBC_THREAD_NATIVE");
    bool native = getenv("FRANKENLIBC_TEST_LIBRARY") != nullptr &&
                  native_setting && !strcmp(native_setting, "1");
    bool creator_error = !strcmp(exit_kind, "creator-error") ||
                         !strcmp(exit_kind, "creator-error-consumed");
    use_late_key = !strcmp(exit_kind, "late-key");
    if (strcmp(exit_kind, "return") && strcmp(exit_kind, "exit") &&
        strcmp(exit_kind, "cancel") && !use_late_key && !use_module &&
        !creator_error && !runtime_callback && !process_exit_case && !compiler_tls_case) return 2;
    // A mismatched executable owner cannot pin an unloadable callback in GNU.
    // This is an explicit rejection check for the native registration policy,
    // not a valid GNU unload-and-call workload.
    if (host_provider && !native) return 77;
    const char *names[] = {"pthread_create", "pthread_join", "pthread_exit",
                          "pthread_cancel", "__cxa_thread_atexit_impl"};
    for (const char *name : names)
        check_provider(name);
    creator_tid = syscall(SYS_gettid);
    creator_tp = (uintptr_t)__builtin_thread_pointer();
    // The owner is the CRT symbol's address. Its stored value is NULL in a
    // non-PIE executable; passing that value is not a valid GNU owner identity.
    if (__cxa_thread_atexit_impl(creator_callback, nullptr, &__dso_handle)) return 3;
    if (process_exit_case) {
        check_provider("exit");
        check_provider("strtok");
        check_provider("inet_ntoa");
        expected_native_backend = native;
        if (atexit(process_exit_check)) return 19;
    }
    if (runtime_retry &&
        !prepare_runtime_pin_retry(!strcmp(exit_kind, "runtime-retry-consumed"), native)) {
        fprintf(stderr, "runtime pin retry precondition failed: %s\n", exit_kind);
        return 18;
    }
    if (runtime_callback) {
        check_provider("__cxa_finalize");
        if (__cxa_atexit(record, (void *)(uintptr_t)6, &runtime_owner_token)) return 15;
        module_callback = __cxa_finalize;
        module_argument = &runtime_owner_token;
        // Any address in the owner image identifies its lifetime. This also
        // verifies admission of a callback in the separately pinned runtime.
        module_owner = (void *)module_callback;
    }
    const char *creator_error_text = nullptr;
    if (creator_error) {
        (void)dlerror();
        if (dlopen("/proc/self/fd/-1", RTLD_NOW)) return 13;
        if (!strcmp(exit_kind, "creator-error-consumed")) {
            creator_error_text = dlerror();
            if (!creator_error_text || !strstr(creator_error_text, "/proc/self/fd/-1"))
                return 14;
        }
    }
    if (use_late_key && pthread_key_create(&late_key, late_key_callback)) return 7;
    void *module = nullptr;
    if (use_module) {
        if (argc != 3) return 2;
        module = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
        if (!module) {
            fprintf(stderr, "TLS fixture dlopen failed: %s\n", dlerror());
            return 8;
        }
        auto callback = (Destructor (*)(void))dlsym(module, "tls_fixture_callback");
        auto owner = (void *(*)(void))dlsym(module, "tls_fixture_owner");
        auto prepare = (void (*)(Emit, void *))dlsym(module, "tls_fixture_prepare");
        auto provider = (void *(*)(void))dlsym(module, "tls_fixture_registration_provider");
        if (!callback || !owner || !prepare || !provider) return 9;
        bool private_loader_hook = provider() != (void *)__cxa_thread_atexit_impl;
        if (private_loader_hook != (native_module && getenv("FRANKENLIBC_TEST_LIBRARY")))
            return 16;
        prepare(module_event, nullptr);
        module_callback = host_owner ? record : callback();
        module_owner = host_provider ? &__dso_handle : owner();
    }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, worker, nullptr)) return 4;
    while (!ready.load(std::memory_order_acquire)) sched_yield();
    // The process callback, on the exiting worker, owns this case's verdict.
    // The creator stays alive with its own pending TLS callback throughout.
    if (process_exit_case)
        for (;;) sched_yield();
    bool rejected = use_module && !native_module && native;
    bool early_unload = false;
    if (use_module) {
        if (dlclose(module)) return 10;
        early_unload = !rejected && event_count.load() != 0;
        if (early_unload) {
            printf("native public TLS dtors %s: FAIL DSO finalized before worker exit\n",
                   exit_kind);
            fflush(stdout);
            _exit(42);
        }
    }
    if (module_callback) release_worker.store(1, std::memory_order_release);
    if (!strcmp(thread_exit_kind, "cancel") && pthread_cancel(thread)) return 5;
    void *result = nullptr;
    if (pthread_join(thread, &result)) return 6;
    if (use_late_key && pthread_key_delete(late_key)) return 11;
    void *expected = !strcmp(thread_exit_kind, "cancel") ? PTHREAD_CANCELED
                                                  : (void *)(uintptr_t)17;
    bool ok = result == expected && !registration_failed.load() &&
              !wrong_thread.load() && !creator_callbacks.load() &&
              event_count.load() == 3 && events[0] == 2 && events[1] == 3 &&
              events[2] == 1;
    if (creator_error) {
        if (!creator_error_text) creator_error_text = dlerror();
        ok = ok && creator_error_text &&
             strstr(creator_error_text, "/proc/self/fd/-1") && dlerror() == nullptr;
    }
    if (use_late_key) {
        // GNU runs TLS callbacks before POSIX key callbacks. This runtime's
        // hosted key bridge participates in the TLS drain, and native teardown
        // has a final drain after its keys; both execute the late registration.
        bool runtime_keys = getenv("FRANKENLIBC_TEST_LIBRARY") != nullptr;
        int count = runtime_keys ? 5 : 4;
        ok = result == expected && !registration_failed.load() &&
             !wrong_thread.load() && !creator_callbacks.load() &&
             event_count.load() == count && events[0] == 2 && events[1] == 3 &&
             events[2] == 1 && events[3] == 4 && (!runtime_keys || events[4] == 5);
    }
    if (use_module) {
        // A last TLS pin may defer collection until a subsequent close.
        void *remaining = dlopen(argv[2], RTLD_NOW | RTLD_NOLOAD);
        if (remaining && dlclose(remaining)) return 12;
        if (rejected) {
            ok = module_registration.load() == -1 && event_count.load() == 1 &&
                 events[0] == 8 && !wrong_thread.load() &&
                 !creator_callbacks.load();
        } else {
            int callback_event = host_owner ? 0 : 7;
            ok = result == expected && module_registration.load() == 0 &&
                 !early_unload && event_count.load() == 2 &&
                 events[0] == callback_event && events[1] == 8 &&
                 !wrong_thread.load() && !creator_callbacks.load();
        }
    }
    if (runtime_callback) {
        ok = result == expected && module_registration.load() == 0 &&
             event_count.load() == 1 && events[0] == 6 && !wrong_thread.load() &&
             !creator_callbacks.load();
    }
    ok = ok && worker_tid != creator_tid && ((worker_tp == creator_tp) == native);
    printf("native public TLS dtors %s: events=%d [%d,%d,%d] creator=%d "
           "wrong_thread=%d registration_failed=%d module_registration=%d %s\n", exit_kind,
           event_count.load(), events[0], events[1], events[2],
           creator_callbacks.load(), wrong_thread.load(),
           registration_failed.load(), module_registration.load(), ok ? "PASS" : "FAIL");
    fflush(stdout);
    // A broken native implementation has left callbacks on the creator's host
    // queue. Keep that later teardown from masking the before-join assertion.
    if (!ok) _exit(41);
    return 0;
}

#endif
