/* Drive compiler-created native plugin fixtures through the deployed loader.
 * Usage: driver library.so operation [native]
 * Run without LD_PRELOAD for the independently linked host fixture; run with
 * LD_PRELOAD=libfrankenlibc_abi.so and "native" for the dependency-free fixture.
 * The low-byte witness matches dlfcn_native.rs HANDLE_TAG, not a host handle.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <inttypes.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <wchar.h>

/* Pin every selected import to the expected deployed image.
 * Raw newfstatat keeps the witness independent of public stat interposition. */
static int import_provider_matches(void *handle, const char *variable,
                                   const char *selector, unsigned count) {
    const char *expected = getenv(variable);
    struct stat want;
    if (!expected || syscall(SYS_newfstatat, AT_FDCWD, expected, &want, 0)) return 0;
    void *(*select_import)(unsigned, unsigned) =
        (void *(*)(unsigned, unsigned))dlsym(handle, selector);
    if (!select_import) return 0;
    for (unsigned i = 0; i < count; i++) {
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
    if (strcmp(argv[2], "integer_smoke") == 0 &&
        !import_provider_matches(handle, "FLC_INTEGER_EXPECT_PROVIDER", "integer_function", 10)) {
        fputs("integer import provider mismatch\n", stderr);
        dlclose(handle); return 42;
    }
    if (strcmp(argv[2], "ctype_smoke") == 0 &&
        !import_provider_matches(handle, "FLC_CTYPE_EXPECT_PROVIDER", "ctype_function", 19)) {
        fputs("ctype import provider mismatch\n", stderr);
        dlclose(handle); return 42;
    }
    if (strcmp(argv[2], "integer_ext_smoke") == 0 &&
        !import_provider_matches(handle, "FLC_INTEGER_EXT_EXPECT_PROVIDER", "integer_ext_function", 41)) {
        fputs("extended integer import provider mismatch\n", stderr);
        dlclose(handle); return 42;
    }
    int result;
    if (strcmp(argv[2], "integer_ext_smoke") == 0) {
        struct record { uint64_t bits; int64_t offset; int error; };
        int (*lookup)(void) = (int (*)(void))dlsym(handle, "integer_ext_lookup");
        int (*sample)(unsigned, wchar_t *, char *, unsigned *) =
            (int (*)(unsigned, wchar_t *, char *, unsigned *))dlsym(handle, "integer_ext_case");
        int (*probe)(unsigned, const void *, unsigned, int, int, locale_t, struct record *) =
            (int (*)(unsigned, const void *, unsigned, int, int, locale_t, struct record *))
                dlsym(handle, "integer_ext_probe");
        if (!lookup || !sample || !probe) return 70;
        locale_t locale = newlocale(LC_ALL_MASK, "C", (locale_t)0);
        if (!locale) return 74;
        result = lookup();
        unsigned records = 0;
        for (unsigned function = 0; result == 0 && function < 40; function++) {
            for (unsigned j = 0; result == 0 && j < 104; j++) {
                wchar_t wide[6116], before_wide[6116];
                unsigned char narrow[6116], before_narrow[6116];
                for (unsigned k = 0; k < 6116; k++) {
                    wide[k] = 0x1234;
                    narrow[k] = 0x56;
                }
                unsigned length = UINT32_MAX;
                int base = sample(j, wide + 8, (char *)narrow + 8, &length);
                if (length > 5001 || wide[8 + length] || narrow[8 + length]) {
                    result = 75; break;
                }
                for (unsigned k = 0; k < 6116; k++) {
                    if ((k < 8 || k > 8 + length) &&
                        (wide[k] != 0x1234 || narrow[k] != 0x56)) result = 76;
                }
                memcpy(before_wide, wide, sizeof(wide));
                memcpy(before_narrow, narrow, sizeof(narrow));
                for (int end = 0; result == 0 && end < 2; end++) {
                    struct { uint64_t left; struct record record; uint64_t right; } out =
                        {UINT64_C(0x123456789abcdef0), {85, 85, 85}, UINT64_C(0xfedcba9876543210)};
                    result = probe(function, function < 20 ? (void *)(narrow + 8) :
                                   (void *)(wide + 8), length, base, end, locale, &out.record);
                    if (out.left != UINT64_C(0x123456789abcdef0) ||
                        out.right != UINT64_C(0xfedcba9876543210) ||
                        memcmp(wide, before_wide, sizeof(wide)) ||
                        memcmp(narrow, before_narrow, sizeof(narrow))) result = 77;
                    if (result != 0) break;
                    printf("integer_ext %u %u %d %d %016" PRIx64 " %" PRId64 " %d\n",
                           function, j, base, end, out.record.bits, out.record.offset,
                           out.record.error);
                    records++;
                }
            }
        }
        freelocale(locale);
        if (result == 0 && records != 8320) result = 78;
    } else if (strcmp(argv[2], "ctype_smoke") == 0) {
        int (*lookup)(void) = (int (*)(void))dlsym(handle, "ctype_lookup");
        void (*probe)(int, int *) = (void (*)(int, int *))dlsym(handle, "ctype_probe");
        if (!lookup || !probe) return 70;
        result = lookup();
        if (result == 0) for (int c = -128; c <= 255; c++) {
            int out[35];
            for (unsigned i = 0; i < 35; i++) out[i] = 0x12345678;
            probe(c, out + 1);
            if (out[0] != 0x12345678 || out[34] != 0x12345678) return 73;
            printf("ctype %d", c);
            for (unsigned i = 1; i < 34; i++) printf(" %d", out[i]);
            putchar('\n');
        }
    } else if (strncmp(argv[2], "cancel", 6) == 0) {
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
