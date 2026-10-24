/* The initial thread has a different lifetime from the process. Compile this
 * as C, C with exceptions, and C++ to exercise all GNU cleanup conventions. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __cplusplus
#include <atomic>
static std::atomic<int> ready(0);
#define STORE_READY() ready.store(1, std::memory_order_release)
#define LOAD_READY() ready.load(std::memory_order_acquire)
#else
#include <stdatomic.h>
static _Atomic int ready;
#define STORE_READY() atomic_store_explicit(&ready, 1, memory_order_release)
#define LOAD_READY() atomic_load_explicit(&ready, memory_order_acquire)
#endif

static unsigned constructors;
static pthread_key_t key;
static pthread_t initial_thread;
static void *expected_result;
static int cancel_from_worker;

static void event(char ch) {
    if (syscall(SYS_write, STDOUT_FILENO, &ch, 1) != 1) _exit(119);
}

static void check_provider(const char *symbol, const char *expected) {
    if (!expected) return;
    void *address = dlsym(RTLD_DEFAULT, symbol);
    Dl_info info;
    struct stat actual, wanted;
    if (!address || !dladdr(address, &info) || !info.dli_fname ||
        stat(info.dli_fname, &actual) || stat(expected, &wanted) ||
        actual.st_dev != wanted.st_dev || actual.st_ino != wanted.st_ino) {
        static const char error[] = "WRONG STARTUP/THREAD PROVIDER\n";
        (void)!syscall(SYS_write, STDERR_FILENO, error, sizeof(error) - 1);
        _exit(117);
    }
}

static void constructor_atexit(void) { event('A'); }
static void main_atexit(void) { event('E'); }

__attribute__((constructor)) static void initialize(void) {
    const char *library = getenv("FRANKENLIBC_TEST_LIBRARY");
    const char *startup = getenv("FRANKENLIBC_TEST_STARTUP_LIBRARY");
    check_provider("__libc_start_main", startup ? startup : library);
    const char *symbols[] = {"pthread_exit", "pthread_cancel", "pthread_join",
                            "pthread_key_create", "pthread_setspecific", "exit"};
    for (unsigned i = 0; i < sizeof(symbols) / sizeof(symbols[0]); ++i)
        check_provider(symbols[i], library);
    if (++constructors != 1 || atexit(constructor_atexit) != 0 ||
        setenv("FRANKENLIBC_MAIN_CTOR_VALUE", "retained", 1) != 0 ||
        unsetenv("FRANKENLIBC_MAIN_CTOR_DROP") != 0) _exit(118);
    event('I');
    if (getenv("FRANKENLIBC_MAIN_CTOR_EXIT")) exit(29);
}

__attribute__((destructor)) static void finalize(void) { event('D'); }

static void key_destructor(void *value) {
    event('K');
    uintptr_t round = (uintptr_t)value;
    if (round < 3 && pthread_setspecific(key, (void *)(round + 1))) _exit(118);
}

static void cleanup(void *value) { event((char)(uintptr_t)value); }

#ifdef __cplusplus
struct LocalCleanup { ~LocalCleanup() { event('R'); } };
struct TlsCleanup { ~TlsCleanup() { event('T'); } };
static thread_local TlsCleanup tls_cleanup;
#endif

static void *survivor(void *unused) {
    (void)unused;
    while (!LOAD_READY()) sched_yield();
    if (cancel_from_worker && pthread_cancel(initial_thread)) _exit(118);
    void *result = NULL;
    if (pthread_join(initial_thread, &result) || result != expected_result) _exit(118);
    event('J');
    /* Last-worker termination must also flush native FILE buffers. */
    if (fputs("B", stdout) < 0) _exit(118);
    return NULL;
}

int main(int argc, char **argv, char **envp) {
    int environment_value = 0;
    for (char **entry = envp; entry && *entry; ++entry) {
        if (!strcmp(*entry, "FRANKENLIBC_MAIN_CTOR_VALUE=retained")) environment_value = 1;
        if (!strncmp(*entry, "FRANKENLIBC_MAIN_CTOR_DROP=",
                     sizeof("FRANKENLIBC_MAIN_CTOR_DROP=") - 1)) return 118;
    }
    if (argc != 2 || constructors != 1 ||
        !environment_value || getenv("FRANKENLIBC_MAIN_CTOR_DROP") ||
        !getenv("FRANKENLIBC_MAIN_CTOR_VALUE") ||
        strcmp(getenv("FRANKENLIBC_MAIN_CTOR_VALUE"), "retained") ||
        atexit(main_atexit) || pthread_key_create(&key, key_destructor) ||
        pthread_setspecific(key, (void *)1)) return 118;
    event('M');
#ifdef __cplusplus
    LocalCleanup local_cleanup;
    (void)&tls_cleanup;
#endif
    const char *scenario = argv[1];
    initial_thread = pthread_self();
    int worker = !strcmp(scenario, "worker-exit") ||
                 !strcmp(scenario, "worker-cancel") ||
                 !strcmp(scenario, "worker-self-cancel");
    int self_cancel = !strcmp(scenario, "self-cancel") ||
                      !strcmp(scenario, "worker-self-cancel") ||
                      !strcmp(scenario, "disabled-cancel");
    cancel_from_worker = !strcmp(scenario, "worker-cancel");
    expected_result = (self_cancel || cancel_from_worker) ? PTHREAD_CANCELED : (void *)23;
    int pipefd[2];
    if (cancel_from_worker && pipe(pipefd)) return 118;
    if (worker) {
        pthread_t child;
        if (pthread_create(&child, NULL, survivor, NULL)) return 118;
    }
    int status = 23;
    pthread_cleanup_push(cleanup, (void *)(uintptr_t)'1');
    pthread_cleanup_push(cleanup, (void *)(uintptr_t)'2');
    STORE_READY();
    if (!strcmp(scenario, "exit")) exit(23);
    if (!strcmp(scenario, "negative-return")) status = -105;
    if (!strcmp(scenario, "fork-exit")) {
        pid_t child = fork();
        if (child < 0) return 118;
        if (child == 0) pthread_exit((void *)23);
        int child_status;
        if (waitpid(child, &child_status, 0) != child ||
            !WIFEXITED(child_status) || WEXITSTATUS(child_status)) return 118;
        event('F');
    } else if (self_cancel) {
        if (!strcmp(scenario, "disabled-cancel") &&
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)) _exit(118);
        if (pthread_cancel(pthread_self())) _exit(118);
        if (!strcmp(scenario, "disabled-cancel")) {
            event('X');
            if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) _exit(118);
        }
        pthread_testcancel();
        _exit(118);
    } else if (cancel_from_worker) {
        char byte;
        (void)!read(pipefd[0], &byte, 1);
        _exit(118);
    } else if (!strcmp(scenario, "thread-exit") || worker) {
        pthread_exit((void *)23);
    }
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    if (fputs("B", stdout) < 0) return 118;
    return status;
}
