/* fixture_pthread.c — pthread_mutex_* under LD_PRELOAD
 * Part of frankenlibc C fixture suite (bd-3jh).
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <dlfcn.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static int test_mutex_init_destroy(void) {
    pthread_mutex_t mtx;
    if (pthread_mutex_init(&mtx, NULL) != 0) {
        fprintf(stderr, "FAIL: pthread_mutex_init\n"); return 1;
    }
    if (pthread_mutex_destroy(&mtx) != 0) {
        fprintf(stderr, "FAIL: pthread_mutex_destroy\n"); return 1;
    }
    return 0;
}

static int test_mutex_lock_unlock(void) {
    pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
    if (pthread_mutex_lock(&mtx) != 0) {
        fprintf(stderr, "FAIL: pthread_mutex_lock\n"); return 1;
    }
    if (pthread_mutex_unlock(&mtx) != 0) {
        fprintf(stderr, "FAIL: pthread_mutex_unlock\n"); return 1;
    }
    pthread_mutex_destroy(&mtx);
    return 0;
}

static int test_mutex_trylock(void) {
    pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

    /* trylock should succeed on unlocked mutex */
    if (pthread_mutex_trylock(&mtx) != 0) {
        fprintf(stderr, "FAIL: trylock on unlocked\n"); return 1;
    }
    pthread_mutex_unlock(&mtx);
    pthread_mutex_destroy(&mtx);
    return 0;
}

static int test_mutex_unlock_without_lock(void) {
    pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
    int rc = pthread_mutex_unlock(&mtx);
    if (rc != EPERM) {
        fprintf(stderr, "FAIL: unlock without lock rc=%d expected=%d\n", rc, EPERM);
        pthread_mutex_destroy(&mtx);
        return 1;
    }
    pthread_mutex_destroy(&mtx);
    return 0;
}

static int test_mutex_destroy_while_locked(void) {
    pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
    if (pthread_mutex_lock(&mtx) != 0) {
        fprintf(stderr, "FAIL: lock before destroy-while-locked\n");
        pthread_mutex_destroy(&mtx);
        return 1;
    }
    int rc = pthread_mutex_destroy(&mtx);
    if (rc != EBUSY) {
        fprintf(stderr, "FAIL: destroy while locked rc=%d expected=%d\n", rc, EBUSY);
        pthread_mutex_unlock(&mtx);
        pthread_mutex_destroy(&mtx);
        return 1;
    }
    pthread_mutex_unlock(&mtx);
    pthread_mutex_destroy(&mtx);
    return 0;
}

/* Shared state for threaded test */
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_counter = 0;
#define THREAD_ITERS 10000

static void *increment_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < THREAD_ITERS; i++) {
        pthread_mutex_lock(&g_mtx);
        g_counter++;
        pthread_mutex_unlock(&g_mtx);
    }
    return NULL;
}

static int test_mutex_contention(void) {
    g_counter = 0;
    const int nthreads = 4;
    pthread_t threads[4];

    for (int i = 0; i < nthreads; i++) {
        if (pthread_create(&threads[i], NULL, increment_thread, NULL) != 0) {
            fprintf(stderr, "FAIL: pthread_create %d\n", i); return 1;
        }
    }
    for (int i = 0; i < nthreads; i++) {
        pthread_join(threads[i], NULL);
    }

    int expected = nthreads * THREAD_ITERS;
    if (g_counter != expected) {
        fprintf(stderr, "FAIL: counter=%d expected=%d (race condition)\n",
                g_counter, expected);
        return 1;
    }
    return 0;
}

static int test_pthread_self_equal(void) {
    pthread_t self = pthread_self();
    if (!pthread_equal(self, self)) {
        fprintf(stderr, "FAIL: pthread_equal(self, self)\n"); return 1;
    }
    return 0;
}

/* Query kernel state in the first instructions of the user routine. This does
 * not borrow the creator's libc TLS, which the native clone backend currently
 * shares, and cannot accidentally verify only attribute getters/setters. */
struct startup_observation {
    cpu_set_t affinity;
    uint64_t signal_mask;
    int policy;
    struct sched_param scheduling;
    int failed;
    atomic_int called;
};

static void *observe_startup(void *arg) {
    struct startup_observation *out = arg;
    if (syscall(SYS_sched_getaffinity, 0, sizeof(out->affinity), &out->affinity) < 0)
        out->failed = 1;
    if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &out->signal_mask,
                sizeof(out->signal_mask)) < 0)
        out->failed = 1;
    out->policy = (int)syscall(SYS_sched_getscheduler, 0);
    if (out->policy < 0 || syscall(SYS_sched_getparam, 0, &out->scheduling) < 0)
        out->failed = 1;
    atomic_store_explicit(&out->called, 1, memory_order_release);
    return arg;
}

static int create_and_observe(const pthread_attr_t *attr,
                              struct startup_observation *out) {
    memset(out, 0, sizeof(*out));
    atomic_init(&out->called, 0);
    pthread_t thread;
    int rc = pthread_create(&thread, attr, observe_startup, out);
    if (rc != 0)
        return rc;
    void *result = NULL;
    if (pthread_join(thread, &result) != 0 || result != out || out->failed ||
        atomic_load_explicit(&out->called, memory_order_acquire) != 1)
        return EIO;
    return 0;
}

static int startup_attribute_fixture(const char *candidate) {
    if (candidate != NULL) {
        Dl_info provider;
        if (dladdr((void *)pthread_create, &provider) == 0 ||
            strcmp(provider.dli_fname, candidate) != 0) {
            fprintf(stderr, "FAIL: pthread_create is not from the requested candidate\n");
            return 1;
        }
    }
    cpu_set_t original_affinity;
    if (sched_getaffinity(0, sizeof(original_affinity), &original_affinity) != 0)
        return 1;
    int cpu = -1;
    for (int i = 0; i < CPU_SETSIZE; ++i) {
        if (CPU_ISSET(i, &original_affinity)) {
            cpu = i;
            break;
        }
    }
    if (cpu < 0)
        return 1;

    int fails = 0;
    pthread_attr_t attr;
    struct startup_observation child;
    cpu_set_t requested;
    CPU_ZERO(&requested);
    CPU_SET(cpu, &requested);
    if (pthread_attr_init(&attr) != 0 ||
        pthread_attr_setaffinity_np(&attr, sizeof(requested), &requested) != 0)
        return 1;
    int rc = create_and_observe(&attr, &child);
    int ok = rc == 0 && CPU_EQUAL(&child.affinity, &requested);
    printf("startup affinity: %s\n", ok ? "PASS" : "FAIL");
    fails += !ok;
    pthread_attr_destroy(&attr);

    /* An empty allowed-CPU set must fail creation without running user code.
     * Repeat to expose leaked failed-start handles and stack mappings. */
    CPU_ZERO(&requested);
    ok = 1;
    for (int i = 0; i < 16; ++i) {
        if (pthread_attr_init(&attr) != 0 ||
            pthread_attr_setaffinity_np(&attr, sizeof(requested), &requested) != 0)
            return 1;
        rc = create_and_observe(&attr, &child);
        ok &= rc == EINVAL && atomic_load(&child.called) == 0;
        pthread_attr_destroy(&attr);
    }
    printf("startup invalid affinity: %s\n", ok ? "PASS" : "FAIL");
    fails += !ok;

    sigset_t original_mask, parent_mask, child_mask;
    sigemptyset(&parent_mask);
    sigaddset(&parent_mask, SIGUSR2);
    if (pthread_sigmask(SIG_SETMASK, &parent_mask, &original_mask) != 0 ||
        pthread_attr_init(&attr) != 0)
        return 1;
    rc = create_and_observe(&attr, &child);
    uint64_t user_bits = (UINT64_C(1) << (SIGUSR1 - 1)) |
                         (UINT64_C(1) << (SIGUSR2 - 1));
    ok = rc == 0 && (child.signal_mask & user_bits) ==
                   (UINT64_C(1) << (SIGUSR2 - 1));
    printf("startup inherited signal mask: %s\n", ok ? "PASS" : "FAIL");
    fails += !ok;
    sigemptyset(&child_mask);
    sigaddset(&child_mask, SIGUSR1);
    if (pthread_attr_setsigmask_np(&attr, &child_mask) != 0)
        return 1;
    rc = create_and_observe(&attr, &child);
    ok = rc == 0 && (child.signal_mask & user_bits) ==
                   (UINT64_C(1) << (SIGUSR1 - 1));
    printf("startup explicit signal mask: %s\n", ok ? "PASS" : "FAIL");
    fails += !ok;
    uint64_t after_mask = 0;
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &after_mask, sizeof(after_mask));
    ok = (after_mask & user_bits) == (UINT64_C(1) << (SIGUSR2 - 1));
    printf("startup creator signal mask: %s\n", ok ? "PASS" : "FAIL");
    fails += !ok;
    if (pthread_attr_setsigmask_np(&attr, NULL) != 0)
        return 1;
    rc = create_and_observe(&attr, &child);
    ok = rc == 0 && (child.signal_mask & user_bits) ==
                   (UINT64_C(1) << (SIGUSR2 - 1));
    printf("startup cleared signal attribute: %s\n", ok ? "PASS" : "FAIL");
    fails += !ok;
    pthread_attr_destroy(&attr);
    pthread_sigmask(SIG_SETMASK, &original_mask, NULL);

    int original_policy = sched_getscheduler(0);
    struct sched_param original_scheduling, normal = { .sched_priority = 0 };
    if (original_policy < 0 || sched_getparam(0, &original_scheduling) != 0 ||
        sched_setscheduler(0, SCHED_BATCH, &normal) != 0 ||
        pthread_attr_init(&attr) != 0)
        return 1;
    rc = create_and_observe(&attr, &child);
    ok = rc == 0 && child.policy == SCHED_BATCH;
    printf("startup inherited scheduler: %s\n", ok ? "PASS" : "FAIL");
    fails += !ok;
    if (pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) != 0 ||
        pthread_attr_setschedpolicy(&attr, SCHED_OTHER) != 0 ||
        pthread_attr_setschedparam(&attr, &normal) != 0)
        return 1;
    rc = create_and_observe(&attr, &child);
    ok = rc == 0 && child.policy == SCHED_OTHER && child.scheduling.sched_priority == 0;
    printf("startup explicit scheduler: %s\n", ok ? "PASS" : "FAIL");
    fails += !ok;
    struct sched_param realtime = { .sched_priority = 1 };
    if (pthread_attr_setschedpolicy(&attr, SCHED_FIFO) != 0 ||
        pthread_attr_setschedparam(&attr, &realtime) != 0)
        return 1;
    rc = create_and_observe(&attr, &child);
    ok = (rc == EPERM && atomic_load(&child.called) == 0) ||
         (rc == 0 && child.policy == SCHED_FIFO && child.scheduling.sched_priority == 1);
    printf("startup realtime permission: %s\n", ok ? "PASS" : "FAIL");
    fails += !ok;
    pthread_attr_destroy(&attr);
    if (sched_setscheduler(0, original_policy, &original_scheduling) != 0)
        return 1;
    cpu_set_t after_affinity;
    ok = sched_getaffinity(0, sizeof(after_affinity), &after_affinity) == 0 &&
         CPU_EQUAL(&after_affinity, &original_affinity);
    printf("startup creator affinity: %s\n", ok ? "PASS" : "FAIL");
    fails += !ok;
    pthread_attr_t saved_defaults;
    CPU_ZERO(&requested);
    CPU_SET(cpu, &requested);
    if (pthread_getattr_default_np(&saved_defaults) != 0 ||
        pthread_attr_init(&attr) != 0 ||
        pthread_attr_setaffinity_np(&attr, sizeof(requested), &requested) != 0 ||
        pthread_attr_setsigmask_np(&attr, &child_mask) != 0 ||
        pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED) != 0 ||
        pthread_attr_setschedpolicy(&attr, SCHED_OTHER) != 0 ||
        pthread_attr_setschedparam(&attr, &normal) != 0 ||
        pthread_setattr_default_np(&attr) != 0)
        return 1;
    rc = create_and_observe(NULL, &child);
    ok = rc == 0 && CPU_EQUAL(&child.affinity, &requested) &&
         (child.signal_mask & user_bits) == (UINT64_C(1) << (SIGUSR1 - 1)) &&
         child.policy == SCHED_OTHER && child.scheduling.sched_priority == 0;
    printf("startup process default attributes: %s\n", ok ? "PASS" : "FAIL");
    fails += !ok;
    pthread_attr_t invalid_defaults;
    size_t stack_size = 1024 * 1024;
    void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED || pthread_attr_init(&invalid_defaults) != 0 ||
        pthread_attr_setstack(&invalid_defaults, stack, stack_size) != 0)
        return 1;
    ok = pthread_setattr_default_np(&invalid_defaults) == EINVAL;
    printf("startup rejects caller-owned default stack: %s\n", ok ? "PASS" : "FAIL");
    fails += !ok;
    pthread_attr_destroy(&invalid_defaults);
    munmap(stack, stack_size);
    rc = create_and_observe(NULL, &child);
    ok = rc == 0 && CPU_EQUAL(&child.affinity, &requested) &&
         (child.signal_mask & user_bits) == (UINT64_C(1) << (SIGUSR1 - 1)) &&
         child.policy == SCHED_OTHER && child.scheduling.sched_priority == 0;
    printf("startup rejected defaults preserve prior settings: %s\n", ok ? "PASS" : "FAIL");
    fails += !ok;
    if (pthread_setattr_default_np(&saved_defaults) != 0)
        return 1;
    pthread_attr_destroy(&saved_defaults);
    pthread_attr_destroy(&attr);
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &after_mask, sizeof(after_mask));
    rc = create_and_observe(NULL, &child);
    ok = rc == 0 && CPU_EQUAL(&child.affinity, &original_affinity) &&
         (child.signal_mask & user_bits) == (after_mask & user_bits) &&
         child.policy == original_policy;
    printf("startup restored process defaults: %s\n", ok ? "PASS" : "FAIL");
    fails += !ok;
    printf("fixture_pthread startup attributes: %s (14 cases)\n", fails ? "FAIL" : "PASS");
    return fails != 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--startup-attributes") == 0)
        return startup_attribute_fixture(argc >= 3 ? argv[2] : NULL);
    int fails = 0;
    fails += test_mutex_init_destroy();
    fails += test_mutex_lock_unlock();
    fails += test_mutex_trylock();
    fails += test_mutex_unlock_without_lock();
    fails += test_mutex_destroy_while_locked();
    fails += test_mutex_contention();
    fails += test_pthread_self_equal();

    pthread_mutex_destroy(&g_mtx);

    if (fails) {
        fprintf(stderr, "fixture_pthread: %d FAILED\n", fails);
        return 1;
    }
    printf("fixture_pthread: PASS (7 tests)\n");
    return 0;
}
