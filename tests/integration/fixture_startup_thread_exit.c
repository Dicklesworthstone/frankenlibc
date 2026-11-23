/* The initial thread has a different lifetime from the process. Compile this
 * as C, C with exceptions, and C++ to exercise all GNU cleanup conventions. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <linux/futex.h>
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
static std::atomic<int> initial_alive(1);
#define STORE_READY() ready.store(1, std::memory_order_release)
#define LOAD_READY() ready.load(std::memory_order_acquire)
#define LOAD_INITIAL_ALIVE() initial_alive.load(std::memory_order_acquire)
#else
#include <stdatomic.h>
static _Atomic int ready;
static _Atomic int initial_alive = 1;
#define STORE_READY() atomic_store_explicit(&ready, 1, memory_order_release)
#define LOAD_READY() atomic_load_explicit(&ready, memory_order_acquire)
#define LOAD_INITIAL_ALIVE() atomic_load_explicit(&initial_alive, memory_order_acquire)
#endif

static unsigned constructors;
static pthread_key_t key;
static pthread_key_t exit_key;
static pthread_t initial_thread;
static pthread_t exiting_worker;
static int *exiting_worker_errno;
static int verify_worker_identity;
static void *expected_result;
static int cancel_from_worker;
static int wait_initial_kernel_exit;
static int detach_survivor;

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
static void main_atexit(void) {
    if (verify_worker_identity) {
        /* Process callbacks still execute on the last worker. Its identity,
         * errno cell and private key storage must outlive these callbacks. */
        if (!pthread_equal(pthread_self(), exiting_worker) ||
            &errno != exiting_worker_errno ||
            pthread_getspecific(exit_key) != NULL ||
            pthread_setspecific(exit_key, (void *)(uintptr_t)47) ||
            pthread_getspecific(exit_key) != (void *)(uintptr_t)47) _exit(116);
    }
    event('E');
}

__attribute__((constructor)) static void initialize(void) {
    const char *library = getenv("FRANKENLIBC_TEST_LIBRARY");
    const char *startup = getenv("FRANKENLIBC_TEST_STARTUP_LIBRARY");
    check_provider("__libc_start_main", startup ? startup : library);
    const char *symbols[] = {"pthread_create", "pthread_detach", "pthread_exit",
                            "pthread_cancel", "pthread_join",
                            "pthread_key_create", "pthread_setspecific", "exit",
                            "pthread_self", "pthread_getspecific", "__errno_location"};
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
    if (detach_survivor && pthread_detach(pthread_self())) _exit(118);
    if (cancel_from_worker && pthread_cancel(initial_thread)) _exit(118);
    if (wait_initial_kernel_exit) {
        /* The kernel clears this word after initial-thread teardown. Waiting
         * here isolates last-worker process exit from initial-thread join
         * support, which the separate worker-exit scenario still exercises. */
        while (LOAD_INITIAL_ALIVE()) {
            long waited = syscall(SYS_futex, &initial_alive, FUTEX_WAIT, 1,
                                  NULL, NULL, 0);
            if (waited && errno != EINTR && errno != EAGAIN) _exit(118);
        }
    } else {
        void *result = NULL;
        if (pthread_join(initial_thread, &result) || result != expected_result) _exit(118);
    }
    exiting_worker = pthread_self();
    exiting_worker_errno = &errno;
    if (pthread_setspecific(exit_key, (void *)(uintptr_t)31)) _exit(118);
    verify_worker_identity = 1;
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
        pthread_key_create(&exit_key, NULL) ||
        pthread_setspecific(key, (void *)1)) return 118;
    event('M');
#ifdef __cplusplus
    LocalCleanup local_cleanup;
    (void)&tls_cleanup;
#endif
    const char *scenario = argv[1];
    initial_thread = pthread_self();
    detach_survivor = !strcmp(scenario, "worker-last-detached");
    wait_initial_kernel_exit = !strcmp(scenario, "worker-last-exit") || detach_survivor;
    if (wait_initial_kernel_exit && syscall(SYS_set_tid_address, &initial_alive) <= 0)
        return 118;
    int worker = !strcmp(scenario, "worker-exit") ||
                 !strcmp(scenario, "worker-cancel") ||
                 !strcmp(scenario, "worker-self-cancel") || wait_initial_kernel_exit;
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
        if (child == 0) {
            if (pthread_getspecific(key) != (void *)1) _exit(118);
            pthread_exit((void *)23);
        }
        int child_status;
        if (waitpid(child, &child_status, 0) != child ||
            !WIFEXITED(child_status) || WEXITSTATUS(child_status) ||
            pthread_getspecific(key) != (void *)1) return 118;
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
