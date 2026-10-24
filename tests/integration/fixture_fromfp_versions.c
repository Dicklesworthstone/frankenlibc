#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* bd-dzsk9d: integer-return GLIBC_2.25/26/27 and floating-return
   GLIBC_2.43 must never share an entry point. No new glibc headers needed. */
static unsigned checks;
static void *lookup(void *lib, const char *name, const char *version) {
    dlerror();
    void *p = dlvsym(lib, name, version);
    const char *error = dlerror();
    if (!p || error) {
        fprintf(stderr, "%s@%s: %s\n", name, version, error ? error : "null");
        exit(1);
    }
    return p;
}
#define REQUIRE(c, name) do { \
    ++checks; \
    if (!(c)) { fprintf(stderr, "%s: failed at line %d\n", name, __LINE__); exit(1); } \
} while (0)
#define SIGNED(T, suffix, version, family) do { \
    const char *name = #family #suffix; \
    int64_t (*old)(T, int, unsigned) = lookup(lib, name, version); \
    T (*current)(T, int, unsigned) = lookup(lib, name, "GLIBC_2.43"); \
    void *normal = dlsym(lib, name); \
    REQUIRE((void *)old != (void *)current, name); \
    REQUIRE(normal == (void *)current, name); \
    REQUIRE(old((T)-7.5, 4, 16) == -8, name); \
    REQUIRE(current((T)-7.5, 4, 16) == (T)-8, name); \
    REQUIRE(current((T)6.5, 4, 16) == (T)6, name); \
    REQUIRE(current((T)6.5, 3, 16) == (T)7, name); \
    REQUIRE(current((T)0x1p100, 2, 128) == (T)0x1p100, name); \
} while (0)
#define UNSIGNED(T, suffix, version, family) do { \
    const char *name = #family #suffix; \
    uint64_t (*old)(T, int, unsigned) = lookup(lib, name, version); \
    T (*current)(T, int, unsigned) = lookup(lib, name, "GLIBC_2.43"); \
    void *normal = dlsym(lib, name); \
    REQUIRE((void *)old != (void *)current, name); \
    REQUIRE(normal == (void *)current, name); \
    REQUIRE(old((T)7.5, 4, 16) == 8, name); \
    REQUIRE(current((T)7.5, 4, 16) == (T)8, name); \
    REQUIRE(current((T)6.5, 4, 16) == (T)6, name); \
    REQUIRE(current((T)6.5, 3, 16) == (T)7, name); \
    REQUIRE(current((T)0x1p100, 2, 128) == (T)0x1p100, name); \
} while (0)
#define FAMILY(T, suffix, version) do { \
    SIGNED(T, suffix, version, fromfp); \
    SIGNED(T, suffix, version, fromfpx); \
    UNSIGNED(T, suffix, version, ufromfp); \
    UNSIGNED(T, suffix, version, ufromfpx); \
} while (0)
int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s LIBRARY\n", argv[0]); return 2; }
    void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!lib) { fprintf(stderr, "%s\n", dlerror()); return 1; }
    FAMILY(double, , "GLIBC_2.25");
    FAMILY(float, f, "GLIBC_2.25");
    FAMILY(long double, l, "GLIBC_2.25");
    FAMILY(float, f32, "GLIBC_2.27");
    FAMILY(double, f64, "GLIBC_2.27");
    FAMILY(double, f32x, "GLIBC_2.27");
    FAMILY(long double, f64x, "GLIBC_2.27");
#if defined(__FLT128_MANT_DIG__)
    FAMILY(_Float128, f128, "GLIBC_2.26");
#else
#error "The fromfp ABI gate requires binary128 support"
#endif
    REQUIRE(dlclose(lib) == 0, "dlclose");
    printf("fromfp ABI versions: %u checks passed\n", checks);
    return 0;
}
