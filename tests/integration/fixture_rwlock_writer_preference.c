/* PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP: while a writer waits, new
 * readers do not get in (gnulib's glthread rwlocks request this kind; gnulib
 * test-rwlock1). fl stored the kind but kept one reader-preferring policy.
 * The default kind still lets a reader join past a waiting writer. A writer
 * that times out lets blocked readers through again. Output matches glibc.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static pthread_rwlock_t lock;
static pthread_rwlock_t lock_static_init = PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP;

static void *writer(void *arg) {
    pthread_rwlock_t *l = arg;
    pthread_rwlock_wrlock(l);
    pthread_rwlock_unlock(l);
    return NULL;
}

static struct timespec in_ms(int ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += (long)ms * 1000000;
    while (ts.tv_nsec >= 1000000000) {
        ts.tv_nsec -= 1000000000;
        ts.tv_sec++;
    }
    return ts;
}

static void scenario(const char *name, pthread_rwlock_t *l) {
    pthread_rwlock_rdlock(l); /* first reader holds the lock */
    pthread_t w;
    pthread_create(&w, NULL, writer, l);
    usleep(100000); /* the writer is now waiting */
    int t = pthread_rwlock_tryrdlock(l);
    if (t == 0) pthread_rwlock_unlock(l);
    struct timespec ts = in_ms(100);
    int tr = pthread_rwlock_timedrdlock(l, &ts);
    if (tr == 0) pthread_rwlock_unlock(l);
    pthread_rwlock_unlock(l); /* first reader leaves: the writer runs */
    pthread_join(w, NULL);
    int after = pthread_rwlock_tryrdlock(l);
    if (after == 0) pthread_rwlock_unlock(l);
    printf("%-22s tryrdlock=%d timedrdlock=%d after writer=%d\n", name, t, tr, after);
}

int main(void) {
    pthread_rwlockattr_t a;
    pthread_rwlockattr_init(&a);
    pthread_rwlockattr_setkind_np(&a, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    pthread_rwlock_init(&lock, &a);
    scenario("prefer-writer", &lock);
    pthread_rwlock_destroy(&lock);
    scenario("static initializer", &lock_static_init);

    pthread_rwlockattr_setkind_np(&a, PTHREAD_RWLOCK_PREFER_READER_NP);
    pthread_rwlock_init(&lock, &a);
    scenario("prefer-reader", &lock);
    pthread_rwlock_destroy(&lock);
    pthread_rwlock_init(&lock, NULL);
    scenario("default", &lock);

    /* A writer that gives up lets the readers it was holding back in. */
    pthread_rwlock_init(&lock, &a);
    pthread_rwlockattr_setkind_np(&a, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    pthread_rwlock_destroy(&lock);
    pthread_rwlock_init(&lock, &a);
    pthread_rwlock_rdlock(&lock);
    struct timespec ts = in_ms(50);
    int wt = pthread_rwlock_timedwrlock(&lock, &ts); /* same thread: times out */
    int rd = pthread_rwlock_tryrdlock(&lock);
    printf("timed-out writer: timedwrlock=%d then tryrdlock=%d\n", wt, rd);
    return 0;
}
