#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/* Threads hammer malloc/free while ITIMER_PROF signals land mid-allocation and
   the handler itself mallocs/frees (reentrant allocator entry on the same
   thread). Every block is filled and checked, so a slot shared between two
   live allocations shows up as corruption. fl hung forever when the handler
   waited on an allocator lock its own interrupted frame held (strict: the
   stats combiner lock; hardened: the membrane arena and page-oracle locks,
   then the native-fallback table lock -- bd-na6ede).

   malloc is not async-signal-safe, and glibc itself deadlocks here: its
   handler malloc can miss tcache and wait for the arena lock the interrupted
   _int_malloc holds (observed, ~1 run in 5). fl promises to survive it (a
   reentrant allocation takes its bootstrap path), so the handler allocates
   only under fl, detected by an fl-only export; under glibc -- the smoke
   battery's baseline -- it runs the same workload with a counting handler and
   prints the same line. */
#define HANDLER_SIZE 24
#define WORKER_MIN 100
#define WORKER_MAX 300
#define WORKERS 8

static volatile long handler_allocs;
static pthread_barrier_t armed;
static int handler_mallocs; /* set when running under frankenlibc */

static void on_prof(int sig) {
    (void)sig;
    if (!handler_mallocs) {
        handler_allocs++;
        return;
    }
    unsigned char *p = malloc(HANDLER_SIZE);
    if (p) {
        memset(p, 0x5a, HANDLER_SIZE);
        for (int i = 0; i < HANDLER_SIZE; i++)
            if (p[i] != 0x5a) abort();
        free(p);
        handler_allocs++;
    }
}

static void warm_handler_bin(void) {
    free(malloc(HANDLER_SIZE));
}

static void *worker(void *arg) {
    unsigned seed = (unsigned)(long)arg;
    unsigned char *live[64] = {0};
    size_t len[64] = {0};
    warm_handler_bin();
    pthread_barrier_wait(&armed); /* timer starts once every thread is warm */
    pthread_barrier_wait(&armed);
    /* 250k per thread: the pre-fix library deadlocks in both modes; the fixed
       one finishes in ~0.1 s strict and ~3 s hardened (inside the 10 s smoke
       timeout -- hardened multi-threaded malloc is itself ~200x glibc). */
    for (long i = 0; i < 250000; i++) {
        int k = rand_r(&seed) & 63;
        if (live[k]) {
            for (size_t j = 0; j < len[k]; j++)
                if (live[k][j] != (unsigned char)k) {
                    fprintf(stderr, "corruption slot %d\n", k);
                    abort();
                }
            free(live[k]);
            live[k] = NULL;
        } else {
            len[k] = WORKER_MIN + (rand_r(&seed) % (WORKER_MAX - WORKER_MIN + 1));
            live[k] = malloc(len[k]);
            memset(live[k], k, len[k]);
        }
    }
    for (int k = 0; k < 64; k++) free(live[k]);
    return NULL;
}

int main(void) {
    handler_mallocs = dlsym(RTLD_DEFAULT, "__frankenlibc_is_runtime_ready") != NULL;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_prof;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGPROF, &sa, NULL);
    pthread_barrier_init(&armed, NULL, WORKERS + 1);
    pthread_t t[WORKERS];
    for (long i = 0; i < WORKERS; i++) pthread_create(&t[i], NULL, worker, (void *)(i + 1));
    warm_handler_bin();
    pthread_barrier_wait(&armed);
    struct itimerval it = {{0, 200}, {0, 200}};
    setitimer(ITIMER_PROF, &it, NULL);
    pthread_barrier_wait(&armed);
    for (int i = 0; i < WORKERS; i++) pthread_join(t[i], NULL);
    struct itimerval off = {{0, 0}, {0, 0}};
    setitimer(ITIMER_PROF, &off, NULL);
    printf("ok handler_allocs>0=%d\n", handler_allocs > 0);
    return 0;
}
