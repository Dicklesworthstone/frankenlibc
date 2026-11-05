/* Drive compiler-created native plugin fixtures through the deployed loader.
 * Usage: driver library.so operation [native]
 * Run without LD_PRELOAD for the independently linked host fixture; run with
 * LD_PRELOAD=libfrankenlibc_abi.so and "native" for the dependency-free fixture.
 * The low-byte witness matches dlfcn_native.rs HANDLE_TAG, not a host handle.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Pin every integer import and its errno slot to the expected deployed image.
 * Raw newfstatat keeps the witness independent of public stat interposition. */
static int integer_provider_matches(void *handle) {
    const char *expected = getenv("FLC_INTEGER_EXPECT_PROVIDER");
    struct stat want;
    if (!expected || syscall(SYS_newfstatat, AT_FDCWD, expected, &want, 0)) return 0;
    void *(*select_import)(unsigned, unsigned) =
        (void *(*)(unsigned, unsigned))dlsym(handle, "integer_function");
    if (!select_import) return 0;
    for (unsigned i = 0; i < 10; i++) {
        Dl_info info;
        struct stat actual;
        if (!dladdr(select_import(i, 0), &info) || !info.dli_fname ||
            syscall(SYS_newfstatat, AT_FDCWD, info.dli_fname, &actual, 0) ||
            actual.st_dev != want.st_dev || actual.st_ino != want.st_ino) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) return 64;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 65; }
    if (argc == 4 && ((uintptr_t)handle & 0xff) != 0x4d) {
        fputs("host fallback is not native execution\n", stderr);
        dlclose(handle); return 66;
    }
    if (strcmp(argv[2], "integer_smoke") == 0 && !integer_provider_matches(handle)) {
        fputs("integer import provider mismatch\n", stderr);
        dlclose(handle); return 42;
    }
    int result;
    if (strncmp(argv[2], "cancel", 6) == 0) {
        unsigned which = (unsigned)strtoul(argv[2] + 6, 0, 10);
        if (which > 4) return 67;
        int (*run)(unsigned) = (int (*)(unsigned))dlsym(handle, "cancellation");
        if (!run) return 68;
        result = run(which);
    } else if (strcmp(argv[2], "fortify") == 0) {
        int (*run)(const char *, size_t, int) =
            (int (*)(const char *, size_t, int))dlsym(handle, "checked_protocol");
        if (!run) return 69;
        result = run("head", 4, 127);
    } else {
        int (*run)(void) = (int (*)(void))dlsym(handle, argv[2]);
        if (!run) return 70;
        result = run();
    }
    printf("%s=%d\n", argv[2], result);
    if (dlclose(handle) != 0) return 71;
    return result == 0 ? 0 : 72;
}
