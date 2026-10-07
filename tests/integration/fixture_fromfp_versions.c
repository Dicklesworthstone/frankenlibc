#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* bd-dzsk9d: integer-return GLIBC_2.25/26/27 and floating-return
   GLIBC_2.43 must never share an entry point. No new glibc headers needed. */
static unsigned checks;
static void *host_libm;
/* The C23 entry points must match the host glibc's GLIBC_2.43 ones bit for
   bit, including the domain-error NaN (glibc: quiet, sign bit set) and an
   out-of-range direction (glibc rounds toward zero). */
static const double grid_x[] = {-7.5, -2.5, -1.5, -0.25, -0.0, 0.0, 0.25, 1.5, 2.5,
                                6.5, 127.5, 65535.5, 1e10, 1.0 / 0.0, -1.0 / 0.0};
static const int grid_dir[] = {-1, 0, 1, 2, 3, 4, 5, 100};
static const unsigned grid_width[] = {0, 1, 8, 16, 64, 65, 128};
#define VALUE_BYTES(T) (sizeof(T) == sizeof(long double) ? 10 : sizeof(T))
#define MATCH_HOST(T, name, current) do { \
    T (*host)(T, int, unsigned) = dlvsym(host_libm, name, "GLIBC_2.43"); \
    REQUIRE(host != NULL, name); \
    for (unsigned xi = 0; xi < sizeof grid_x / sizeof *grid_x + 1; xi++) { \
        T x = xi < sizeof grid_x / sizeof *grid_x ? (T)grid_x[xi] : (T)__builtin_nan(""); \
        for (unsigned di = 0; di < sizeof grid_dir / sizeof *grid_dir; di++) \
            for (unsigned wi = 0; wi < sizeof grid_width / sizeof *grid_width; wi++) { \
                T a = current(x, grid_dir[di], grid_width[wi]); \
                T b = host(x, grid_dir[di], grid_width[wi]); \
                ++checks; \
                if (memcmp(&a, &b, VALUE_BYTES(T)) != 0) { \
                    fprintf(stderr, "%s(%g, %d, %u): differs from host glibc\n", name, \
                            (double)x, grid_dir[di], grid_width[wi]); \
                    exit(1); \
                } \
            } \
    } \
} while (0)
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
    MATCH_HOST(T, name, current); \
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
    MATCH_HOST(T, name, current); \
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
    host_libm = dlopen("libm.so.6", RTLD_NOW | RTLD_LOCAL);
    if (!host_libm) { fprintf(stderr, "%s\n", dlerror()); return 1; }
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
