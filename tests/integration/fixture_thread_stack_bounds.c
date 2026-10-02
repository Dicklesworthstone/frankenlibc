/* pthread_getattr_np stack bounds.
 *
 * fl reported every thread's stack as the main thread's [stack] mapping
 * (the current stack pointer outside the reported range) and the main
 * stack as the mapped 132 KiB instead of glibc's RLIMIT_STACK extent.
 * CPython 3.14 sizes its C-stack limits from these values; with them its
 * trashcan deferred deallocations that a finished thread then leaked, deep
 * expressions hit "Parser stack overflowed", and 63 test modules reported
 * leaked Thread objects. Output is compared byte-for-byte with glibc; the
 * main stack's exact size depends on the randomized layout above the
 * initial stack pointer, so only its range is printed.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>

static void report(const char *who, int main_thread) {
    pthread_attr_t attr;
    void *addr = 0;
    size_t size = 0, guard = 0;
    int detach = -1;
    int rc = pthread_getattr_np(pthread_self(), &attr);
    pthread_attr_getstack(&attr, &addr, &size);
    pthread_attr_getguardsize(&attr, &guard);
    pthread_attr_getdetachstate(&attr, &detach);
    pthread_attr_destroy(&attr);
    char probe;
    uintptr_t sp = (uintptr_t)&probe, lo = (uintptr_t)addr;
    printf("%s: rc=%d detach=%d guard=%zu sp_inside=%d", who, rc, detach, guard, sp > lo && sp < lo + size);
    if (main_thread) {
        struct rlimit rl;
        getrlimit(RLIMIT_STACK, &rl);
        printf(" size_within_64KiB_of_rlimit=%d\n", size <= rl.rlim_cur && size + 65536 > rl.rlim_cur);
    } else {
        printf(" size=%zu\n", size);
    }
}

static void *worker(void *arg) {
    report((const char *)arg, 0);
    return NULL;
}

int main(void) {
    report("main", 1);
    /* No size is within 4x below an earlier one, so glibc's stack cache
     * never hands a thread a larger cached stack. Index 0 is the default:
     * RLIMIT_STACK, as a NULL attr gets. */
    size_t sizes[] = {0, 1 << 20, 128 << 10, (8 << 20) + 12345};
    for (int i = 0; i < 4; i++) {
        pthread_attr_t a;
        pthread_attr_init(&a);
        if (sizes[i])
            pthread_attr_setstacksize(&a, sizes[i]);
        if (i == 2)
            pthread_attr_setguardsize(&a, 3 * 4096);
        if (i == 3)
            pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
        char name[32];
        snprintf(name, sizeof name, "thread%d", i);
        pthread_t t;
        if (i == 3) {
            /* Detached: report from inside, then let main wait for output. */
            static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
            pthread_mutex_lock(&m);
            pthread_create(&t, &a, worker, name);
            pthread_attr_destroy(&a);
            struct timespec ts = {0, 200 * 1000 * 1000};
            nanosleep(&ts, NULL);
            pthread_mutex_unlock(&m);
        } else {
            pthread_create(&t, &a, worker, name);
            pthread_attr_destroy(&a);
            pthread_join(t, NULL);
        }
    }
    return 0;
}
