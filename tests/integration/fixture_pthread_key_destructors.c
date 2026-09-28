/* fixture_pthread_key_destructors.c — POSIX key destructors run when a thread
 * exits, by return and by pthread_exit, including destructor re-rounds when a
 * destructor stores a new value (bd-v6cz9v). fl kept keys in its own table
 * while host-created threads exited through the host's start_thread, so no
 * key destructor ever ran. Output must be byte-identical to glibc.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

static pthread_key_t plain, again;
static int plain_calls, again_calls;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void plain_dtor(void *v) {
    pthread_mutex_lock(&lock);
    plain_calls += (int)(intptr_t)v;
    pthread_mutex_unlock(&lock);
}

/* Re-arms itself once: POSIX runs another destructor round for it. */
static void again_dtor(void *v) {
    pthread_mutex_lock(&lock);
    again_calls++;
    pthread_mutex_unlock(&lock);
    if ((intptr_t)v == 1) pthread_setspecific(again, (void *)2);
}

static void *worker(void *arg) {
    pthread_setspecific(plain, (void *)1);
    pthread_setspecific(again, (void *)1);
    if (arg) pthread_exit(NULL);
    return NULL;
}

int main(void) {
    pthread_key_create(&plain, plain_dtor);
    pthread_key_create(&again, again_dtor);
    enum { N = 200 };
    for (int i = 0; i < N; i++) {
        pthread_t t;
        pthread_create(&t, NULL, worker, (i & 1) ? (void *)1 : NULL);
        pthread_join(t, NULL);
    }
    /* The main thread's values are not destroyed at exit. */
    pthread_setspecific(plain, (void *)1000);
    printf("threads=%d plain destructor sum=%d again destructor calls=%d\n", N, plain_calls, again_calls);
    return 0;
}
