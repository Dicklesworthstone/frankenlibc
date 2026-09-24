#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static int (*answer)(void);
static int (*step)(void);
static int worker_before, worker_step, worker_after;

static void *worker(void *unused) {
    (void)unused;
    worker_before = answer();
    worker_step = step();
    worker_after = answer();
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "%s\n", dlerror()); return 3; }
    answer = (int (*)(void))dlvsym(handle, "answer", "FIXTURE_1.0");
    step = (int (*)(void))dlsym(handle, "tls_step");
    void (*set_counter)(int *) = (void (*)(int *))dlsym(handle, "set_finalizer_counter");
    if (!answer || !step || !set_counter) return 4;
    if (dlvsym(handle, "answer", "MISSING_VERSION") != NULL) return 5;
    (void)dlerror();
    int finished = 0;
    set_counter(&finished);
    int before = answer();
    int increment = step();
    int after = answer();
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL) || pthread_join(thread, NULL)) return 6;
    int parent_after = answer();
    if (dlclose(handle)) return 7;
    printf("%d %d %d %d %d %d %d %d\n", before, increment, after,
           worker_before, worker_step, worker_after, parent_after, finished);
    return before == 33 && increment == 4 && after == 34 && worker_before == 33
        && worker_step == 4 && worker_after == 34 && parent_after == 34 && finished == 12 ? 0 : 8;
}
