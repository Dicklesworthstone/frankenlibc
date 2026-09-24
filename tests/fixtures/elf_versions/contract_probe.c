#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    char provider_path[4096], consumer_path[4096];
    int n = snprintf(provider_path, sizeof provider_path, "%s/libversions.so", argv[1]);
    int m = snprintf(consumer_path, sizeof consumer_path, "%s/contract.so", argv[1]);
    if (n < 0 || m < 0 || (size_t)n >= sizeof provider_path || (size_t)m >= sizeof consumer_path) return 2;
    void *provider = dlopen(provider_path, RTLD_NOW | RTLD_GLOBAL);
    if (!provider) { fprintf(stderr, "%s\n", dlerror()); return 1; }
    dlerror();
    void *consumer = dlopen(consumer_path, RTLD_NOW | RTLD_LOCAL);
    const char *error = dlerror();
    if (!strcmp(argv[2], "strong")) {
        if (consumer || !error || !strstr(error, "VERS_2")) return 1;
        if (dlopen(consumer_path, RTLD_NOW | RTLD_NOLOAD)) return 1;
    } else {
        if (!consumer || error) { fprintf(stderr, "%s\n", error ? error : "load failed"); return 1; }
        int (*current)(void) = (int (*)(void))dlsym(consumer, "current_values");
        int (*previous)(void) = (int (*)(void))dlsym(consumer, "previous_values");
        if (!current || !previous || current() != 470 || previous() != 470) return 1;
        if (dlclose(consumer)) return 1;
    }
    // Failure must not destroy the original provider's usable public handle.
    dlerror();
    if (!dlsym(provider, "api") || dlerror() || dlclose(provider)) return 1;
    puts("dependency version contract: PASS");
    return 0;
}
