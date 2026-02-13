/* fixture_pthread.c — pthread_mutex_* under LD_PRELOAD
 * Part of frankenlibc C fixture suite (bd-3jh).
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

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

int main(void) {
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
