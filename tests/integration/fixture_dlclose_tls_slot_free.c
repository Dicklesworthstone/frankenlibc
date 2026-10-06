/* After dlclose of a library whose dynamic TLS block was allocated in this
 * thread, the thread's next __tls_get_addr runs ld.so's _dl_update_slotinfo,
 * which frees that block with the process's free() before clearing the DTV
 * slot. fl's free used dynamic TLS itself (__tls_get_addr), re-entered the
 * update, and freed the same block again: strict mode aborted with "double
 * free or corruption" (PHP at exit after unloading its extensions). */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s PLUGIN\n", argv[0]);
        return 2;
    }
    for (int round = 0; round < 3; round++) {
        void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        if (handle == NULL) {
            printf("dlopen failed\n");
            return 1;
        }
        const char *(*touch)(void) = (const char *(*)(void))dlsym(handle, "plugin_touch");
        if (touch == NULL || touch() == NULL) {
            printf("plugin_touch failed\n");
            return 1;
        }
        if (dlclose(handle) != 0) {
            printf("dlclose failed\n");
            return 1;
        }
        char *p = malloc(64);
        free(p);
        if (getenv("FIXTURE_DLCLOSE_TLS_UNSET") != NULL) {
            return 1;
        }
        printf("round %d ok\n", round);
    }
    return 0;
}
