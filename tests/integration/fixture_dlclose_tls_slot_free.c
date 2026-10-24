/* After dlclose of a library whose dynamic TLS block was allocated in this
 * thread, the thread's next __tls_get_addr runs ld.so's _dl_update_slotinfo,
 * which frees that block with the process's free() before clearing the DTV
 * slot. fl's free used dynamic TLS itself (__tls_get_addr), re-entered the
 * update, and freed the same block again: strict mode aborted with "double
 * free or corruption" (PHP at exit after unloading its extensions). */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int check_system_pathname_dsos(void) {
    const char *libz_paths[] = {
        "/usr/lib/x86_64-linux-gnu/libz.so.1",
        "/lib/x86_64-linux-gnu/libz.so.1",
        NULL
    };
    for (int i = 0; libz_paths[i] != NULL; i++) {
        if (access(libz_paths[i], R_OK) == 0) {
            void *h = dlopen(libz_paths[i], RTLD_NOW | RTLD_LOCAL);
            if (!h) return 1;
            const char *(*zv)(void) = (const char *(*)(void))dlsym(h, "zlibVersion");
            if (!zv || zv()[0] != '1') return 1;
            if (dlclose(h) != 0) return 1;
            break;
        }
    }

    const char *libm_paths[] = {
        "/usr/lib/x86_64-linux-gnu/libm.so.6",
        "/lib/x86_64-linux-gnu/libm.so.6",
        NULL
    };
    for (int i = 0; libm_paths[i] != NULL; i++) {
        if (access(libm_paths[i], R_OK) == 0) {
            void *h = dlopen(libm_paths[i], RTLD_NOW | RTLD_LOCAL);
            if (!h) return 1;
            double (*cos_fn)(double) = (double (*)(double))dlsym(h, "cos");
            if (!cos_fn || cos_fn(0.0) != 1.0) return 1;
            if (dlclose(h) != 0) return 1;
            break;
        }
    }

    const char *opt_libs[][2] = {
        {"/usr/lib/x86_64-linux-gnu/libcrypto.so.3", "OpenSSL_version_num"},
        {"/usr/lib/x86_64-linux-gnu/libssl.so.3", "OPENSSL_init_ssl"},
        {NULL, NULL}
    };
    for (int i = 0; opt_libs[i][0] != NULL; i++) {
        if (access(opt_libs[i][0], R_OK) == 0) {
            void *h = dlopen(opt_libs[i][0], RTLD_NOW | RTLD_LOCAL);
            if (!h) return 1;
            if (dlsym(h, opt_libs[i][1]) == NULL) return 1;
            if (dlclose(h) != 0) return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s PLUGIN\n", argv[0]);
        return 2;
    }
    if (check_system_pathname_dsos() != 0) {
        printf("system pathname dlopen failed\n");
        return 1;
    }
    for (int round = 0; round < 3; round++) {
        void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        if (handle == NULL) {
            printf("dlopen failed\n");
            return 1;
        }
        const char *(*touch)(void) = (const char *(*)(void))dlsym(handle, "plugin_touch");
        if (touch == NULL) {
            printf("plugin_touch dlsym failed\n");
            return 1;
        }
        const char *s1 = touch();
        const char *s2 = touch();
        if (s1 == NULL || s2 == NULL || strcmp(s2, "ie=20") != 0) {
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
