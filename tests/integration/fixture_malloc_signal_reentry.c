#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/* Threads hammer malloc/free while ITIMER_PROF signals land mid-allocation and
   the handler itself mallocs/frees (reentrant allocator entry on the same
   thread). Every block is filled and checked, so a slot shared between two
   live allocations shows up as corruption. Not POSIX-conforming (malloc is not
   async-signal-safe) but common in practice, and glibc survives it; fl hung
   forever when the handler waited on an allocator lock its own interrupted
   frame held (strict: the stats combiner lock; hardened: bd-na6ede). */
static volatile long handler_allocs;

static void on_prof(int sig) {
    (void)sig;
    unsigned char *p = malloc(40);
    if (p) {
        memset(p, 0x5a, 40);
        for (int i = 0; i < 40; i++)
            if (p[i] != 0x5a) abort();
        free(p);
        handler_allocs++;
    }
}

static void *worker(void *arg) {
    unsigned seed = (unsigned)(long)arg;
    unsigned char *live[64] = {0};
    size_t len[64] = {0};
    for (long i = 0; i < 1000000; i++) {
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
            len[k] = 1 + (rand_r(&seed) % 300);
            live[k] = malloc(len[k]);
            memset(live[k], k, len[k]);
        }
    }
    for (int k = 0; k < 64; k++) free(live[k]);
    return NULL;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_prof;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGPROF, &sa, NULL);
    struct itimerval it = {{0, 200}, {0, 200}};
    setitimer(ITIMER_PROF, &it, NULL);
    pthread_t t[8];
    for (long i = 0; i < 8; i++) pthread_create(&t[i], NULL, worker, (void *)(i + 1));
    for (int i = 0; i < 8; i++) pthread_join(t[i], NULL);
    struct itimerval off = {{0, 0}, {0, 0}};
    setitimer(ITIMER_PROF, &off, NULL);
    printf("ok handler_allocs>0=%d\n", handler_allocs > 0);
    return 0;
}
