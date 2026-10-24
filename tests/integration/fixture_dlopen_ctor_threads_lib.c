/* Library for fixture_dlopen_ctor_threads.c: like OpenBLAS, its constructor
 * starts worker threads while dlopen holds the loader lock.
 */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* Like OpenBLAS: the library constructor starts worker threads while the
 * loader lock is held by dlopen. */
#define WORKERS 12
static pthread_t workers[WORKERS];
static volatile int ready;

static void *worker(void *arg) {
    (void)arg;
    char *p = malloc(64);
    memset(p, 1, 64);
    free(p);
    __atomic_fetch_add(&ready, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

__attribute__((constructor)) static void start_workers(void) {
    for (int i = 0; i < WORKERS; i++)
        pthread_create(&workers[i], NULL, worker, NULL);
}

int ctorlib_ready(void) {
    for (int i = 0; i < WORKERS; i++)
        pthread_join(workers[i], NULL);
    return ready;
}
