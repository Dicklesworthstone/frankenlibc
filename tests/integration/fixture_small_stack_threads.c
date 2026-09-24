/* fixture_small_stack_threads.c — threads with small explicit stacks must be
 * creatable under preload (bd-rc0923-epic-eeuy4f.9).
 *
 * glibc carves every loaded module's static TLS out of each new thread's
 * stack. FrankenLibC's static TLS was 127 KB (a per-signal ucontext_t copy,
 * a 1024-entry pthread key table, netdb/fstab buffers), so host
 * pthread_create returned EINVAL for the 32-64 KiB stacks libuv and node use.
 * Output is deterministic and identical under host glibc.
 */
#include <pthread.h>
#include <stdio.h>

static void *worker(void *arg) {
    volatile char buf[2048];
    buf[0] = 1;
    return (void *)((long)arg * 2 + buf[0] - 1);
}

int main(void) {
    const size_t sizes[] = {32768, 65536, 131072};
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        pthread_attr_t attr;
        pthread_t t;
        void *ret = NULL;
        pthread_attr_init(&attr);
        int rc = pthread_attr_setstacksize(&attr, sizes[i]);
        if (rc == 0) rc = pthread_create(&t, &attr, worker, (void *)(long)(i + 1));
        if (rc == 0) rc = pthread_join(t, &ret);
        printf("stack=%zu rc=%d ret=%ld\n", sizes[i], rc, (long)ret);
        pthread_attr_destroy(&attr);
    }
    return 0;
}
