#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *what) {
    const char *error = dlerror();
    fprintf(stderr, "%s: %s\n", what, error ? error : "unexpected result");
    exit(1);
}
static void *open_dso(const char *directory, const char *name, int flags) {
    char path[4096];
    int n = snprintf(path, sizeof path, "%s/%s", directory, name);
    if (n < 0 || (size_t)n >= sizeof path) fail("path");
    void *handle = dlopen(path, flags | RTLD_NOW);
    if (!handle) fail(name);
    return handle;
}
static void *symbol(void *handle, const char *name, const char *version) {
    dlerror();
    void *value = version ? dlvsym(handle, name, version) : dlsym(handle, name);
    if (dlerror() || !value) fail(name);
    return value;
}
static void expect_function(void *handle, const char *name, const char *version, int expected) {
    int (*call)(void) = (int (*)(void))symbol(handle, name, version);
    if (call() != expected) fail(name);
}
static void expect_absent(void *handle, const char *name, const char *version) {
    dlerror();
    void *value = version ? dlvsym(handle, name, version) : dlsym(handle, name);
    const char *error = dlerror();
    if (value || !error) fail("lookup must fail with dlerror");
}
static void *thread_probe(void *handle) {
    int *current = symbol(handle, "tls_value", NULL);
    int *old = symbol(handle, "tls_value", "VERS_1");
    if (current == old || *current != 404 || *old != 303) fail("thread TLS versions");
    *current = 901;
    *old = 902;
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *provider = open_dso(argv[1], "libversions.so", RTLD_GLOBAL);
    expect_function(provider, "api", NULL, 22);
    expect_function(provider, "api", "VERS_1", 11);
    expect_function(provider, "api", "VERS_2", 22);
    expect_function(provider, "dispatch", NULL, 66);
    expect_function(provider, "dispatch", "VERS_1", 55);
    expect_function(provider, "retired", "VERS_1", 33);
    expect_function(provider, "recent", "VERS_2", 44);
    expect_absent(provider, "retired", NULL);
    expect_absent(provider, "recent", NULL);
    expect_absent(provider, "api", "NOT_PRESENT");
    expect_absent(provider, "unversioned", "NOT_PRESENT");
    expect_function(provider, "unversioned", NULL, 77);
    if (*(int *)symbol(provider, "data", NULL) != 202 ||
        *(int *)symbol(provider, "data", "VERS_1") != 101) fail("data versions");
    pthread_t thread;
    if (pthread_create(&thread, NULL, thread_probe, provider) || pthread_join(thread, NULL)) fail("pthread");
    if (*(int *)symbol(provider, "tls_value", NULL) != 404 ||
        *(int *)symbol(provider, "tls_value", "VERS_1") != 303) fail("main TLS versions");
    void *consumer = open_dso(argv[1], "consumer.so", RTLD_LOCAL);
    expect_function(consumer, "current_values", NULL, 694);
    expect_function(consumer, "previous_values", NULL, 470);
    void *legacy = open_dso(argv[1], "legacy.so", RTLD_LOCAL);
    expect_function(legacy, "legacy_values", NULL, 470);
    void *plain = open_dso(argv[1], "unversioned.so", RTLD_LOCAL);
    expect_function(plain, "plain", NULL, 88);
    expect_function(plain, "plain", "ARBITRARY", 88);
    if (dlclose(plain) || dlclose(legacy) || dlclose(consumer) || dlclose(provider)) fail("dlclose");
    puts("versioned lookup, relocations, IFUNC and TLS: PASS");
    return 0;
}
