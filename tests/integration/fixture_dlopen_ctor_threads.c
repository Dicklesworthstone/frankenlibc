/* dlopen of a library whose constructor creates threads, after enough
 * create/join rounds that pthread_t values repeat. Hardened fl deadlocked
 * here (CPython test_pickle importing numpy/OpenBLAS): a new thread's
 * registry insert grew the table under the registry lock, the growth's
 * memset first-touched the membrane TLS cache, whose destructor
 * registration waits for the loader lock -- held by the constructor's
 * pthread_create, which waited for that registry. Output must match glibc.
 * usage: fixture_dlopen_ctor_threads <path to the companion .so>
 */
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static void *noop(void *arg) { return arg; }

int main(int argc, char **argv) {
    const char *lib = argc > 1 ? argv[1] : "./libctor.so";
    /* Recycle thread handles first: glibc reuses pthread_t values (cached
     * stacks), so registry keys repeat. */
    for (int round = 0; round < 40; round++) {
        pthread_t t[8];
        for (int i = 0; i < 8; i++)
            pthread_create(&t[i], NULL, noop, NULL);
        for (int i = 0; i < 8; i++)
            pthread_join(t[i], NULL);
    }
    void *h = dlopen(lib, RTLD_NOW);
    if (!h) {
        printf("dlopen failed: %s\n", dlerror());
        return 1;
    }
    int (*ready)(void) = (int (*)(void))dlsym(h, "ctorlib_ready");
    printf("constructor workers finished: %d\n", ready());
    return 0;
}
