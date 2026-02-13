/* fixture_pthread_mutex_adversarial.c — mutex-only adversarial fixture (bd-1qy)
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#include <errno.h>
#include <pthread.h>
#include <stdio.h>

static int test_mutex_init_destroy(void) {
    pthread_mutex_t mtx;
    if (pthread_mutex_init(&mtx, NULL) != 0) {
        fprintf(stderr, "FAIL: pthread_mutex_init\n");
        return 1;
    }
    if (pthread_mutex_destroy(&mtx) != 0) {
        fprintf(stderr, "FAIL: pthread_mutex_destroy\n");
        return 1;
    }
    return 0;
}

static int test_mutex_lock_trylock_busy_unlock(void) {
    pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
    if (pthread_mutex_lock(&mtx) != 0) {
        fprintf(stderr, "FAIL: pthread_mutex_lock\n");
        pthread_mutex_destroy(&mtx);
        return 1;
    }
    int rc = pthread_mutex_trylock(&mtx);
    if (rc != EBUSY) {
        fprintf(stderr, "FAIL: pthread_mutex_trylock rc=%d expected=%d\n", rc, EBUSY);
        pthread_mutex_unlock(&mtx);
        pthread_mutex_destroy(&mtx);
        return 1;
    }
    if (pthread_mutex_unlock(&mtx) != 0) {
        fprintf(stderr, "FAIL: pthread_mutex_unlock\n");
        pthread_mutex_destroy(&mtx);
        return 1;
    }
    pthread_mutex_destroy(&mtx);
    return 0;
}

static int test_mutex_unlock_without_lock(void) {
    pthread_mutex_t mtx;
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0) {
        fprintf(stderr, "FAIL: pthread_mutexattr_init\n");
        return 1;
    }
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0) {
        fprintf(stderr, "FAIL: pthread_mutexattr_settype(ERRORCHECK)\n");
        pthread_mutexattr_destroy(&attr);
        return 1;
    }
    if (pthread_mutex_init(&mtx, &attr) != 0) {
        fprintf(stderr, "FAIL: pthread_mutex_init(ERRORCHECK)\n");
        pthread_mutexattr_destroy(&attr);
        return 1;
    }
    pthread_mutexattr_destroy(&attr);
    int rc = pthread_mutex_unlock(&mtx);
    if (rc != EPERM) {
        fprintf(stderr, "FAIL: pthread_mutex_unlock without lock rc=%d expected=%d\n", rc, EPERM);
        pthread_mutex_destroy(&mtx);
        return 1;
    }
    pthread_mutex_destroy(&mtx);
    return 0;
}

static int test_mutex_destroy_while_locked(void) {
    pthread_mutex_t mtx;
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0) {
        fprintf(stderr, "FAIL: pthread_mutexattr_init\n");
        return 1;
    }
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0) {
        fprintf(stderr, "FAIL: pthread_mutexattr_settype(ERRORCHECK)\n");
        pthread_mutexattr_destroy(&attr);
        return 1;
    }
    if (pthread_mutex_init(&mtx, &attr) != 0) {
        fprintf(stderr, "FAIL: pthread_mutex_init(ERRORCHECK)\n");
        pthread_mutexattr_destroy(&attr);
        return 1;
    }
    pthread_mutexattr_destroy(&attr);
    if (pthread_mutex_lock(&mtx) != 0) {
        fprintf(stderr, "FAIL: pthread_mutex_lock before destroy\n");
        pthread_mutex_destroy(&mtx);
        return 1;
    }
    int rc = pthread_mutex_destroy(&mtx);
    if (rc != EBUSY) {
        fprintf(stderr, "FAIL: pthread_mutex_destroy while locked rc=%d expected=%d\n", rc, EBUSY);
        pthread_mutex_unlock(&mtx);
        pthread_mutex_destroy(&mtx);
        return 1;
    }
    pthread_mutex_unlock(&mtx);
    pthread_mutex_destroy(&mtx);
    return 0;
}

int main(void) {
    int fails = 0;
    fails += test_mutex_init_destroy();
    fails += test_mutex_lock_trylock_busy_unlock();
    fails += test_mutex_unlock_without_lock();
    fails += test_mutex_destroy_while_locked();

    if (fails) {
        fprintf(stderr, "fixture_pthread_mutex_adversarial: %d FAILED\n", fails);
        return 1;
    }

    printf("fixture_pthread_mutex_adversarial: PASS (4 tests)\n");
    return 0;
}
