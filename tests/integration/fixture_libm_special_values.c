/* libm special-value semantics, compared byte for byte with host glibc by
 * ld_preload_smoke.sh: for every unary double and float function, the result
 * bits and FE_INVALID for quiet NaNs of both signs and with a payload, a
 * signaling NaN, +-inf, and the NaN (if any) a domain error gives at -1, 2, -2.
 *
 * glibc returns a NaN argument quieted with its sign and payload, raising
 * FE_INVALID only for a signaling one; fl's kernels disagreed (exp/log/floor
 * returned an sNaN unquieted and silent, exp2/exp10/lgammaf raised FE_INVALID
 * for a quiet NaN, tan/y0/y1 returned the canonical NaN, tan(+-inf) raised
 * nothing), and the sign of domain-error NaNs differed per function. Finite
 * non-NaN results are not printed: their last-bit accuracy is not this gate's
 * subject. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <float.h>
#include <math.h>
#include <fenv.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static const char *names[] = {
    "acos", "acosh", "asin", "asinh", "atan", "atanh", "cbrt", "ceil", "cos", "cosh", "erf",
    "erfc", "exp", "exp10", "exp2", "expm1", "fabs", "floor", "j0", "j1", "lgamma", "log",
    "log10", "log1p", "log2", "logb", "nearbyint", "rint", "round", "roundeven", "sin", "sinh",
    "sqrt", "tan", "tanh", "tgamma", "trunc", "y0", "y1", "significand", "acospi", "asinpi",
    "atanpi", "cospi", "sinpi", "tanpi", "exp2m1", "exp10m1", "log2p1", "log10p1", "logp1", 0};

static void doubles(void) {
    static const uint64_t ins[] = {
        0xfff8000000000000ull, 0x7ff8000000000000ull, 0xfff8000000000123ull,
        0x7ff4000000000000ull, 0x7ff0000000000000ull, 0xfff0000000000000ull,
        0xbff0000000000000ull, 0x4000000000000000ull, 0xc000000000000000ull};
    for (const char **n = names; *n; n++) {
        double (*f)(double) = (double (*)(double))dlsym(RTLD_DEFAULT, *n);
        if (!f) {
            continue;
        }
        printf("%-12s", *n);
        for (unsigned i = 0; i < sizeof ins / sizeof *ins; i++) {
            double x, r;
            uint64_t b;
            memcpy(&x, &ins[i], sizeof x);
            feclearexcept(FE_ALL_EXCEPT);
            r = f(x);
            int inv = fetestexcept(FE_INVALID) != 0;
            memcpy(&b, &r, sizeof b);
            if (i >= 6 && r == r) {
                printf(" number%s", inv ? "!" : " ");
            } else {
                printf(" %016llx%s", (unsigned long long)b, inv ? "!" : " ");
            }
        }
        printf("\n");
    }
}

static void floats(void) {
    static const uint32_t ins[] = {0xffc00000u, 0x7fc00000u, 0xffc00123u,
                                   0x7fa00000u, 0x7f800000u, 0xff800000u,
                                   0xbf800000u, 0x40000000u, 0xc0000000u};
    for (const char **n = names; *n; n++) {
        char name[32];
        snprintf(name, sizeof name, "%sf", *n);
        float (*f)(float) = (float (*)(float))dlsym(RTLD_DEFAULT, name);
        if (!f) {
            continue;
        }
        printf("%-12s", name);
        for (unsigned i = 0; i < sizeof ins / sizeof *ins; i++) {
            float x, r;
            uint32_t b;
            memcpy(&x, &ins[i], sizeof x);
            feclearexcept(FE_ALL_EXCEPT);
            r = f(x);
            int inv = fetestexcept(FE_INVALID) != 0;
            memcpy(&b, &r, sizeof b);
            if (i >= 6 && r == r) {
                printf(" number%s", inv ? "!" : " ");
            } else {
                printf(" %08x%s", (unsigned)b, inv ? "!" : " ");
            }
        }
        printf("\n");
    }
}

/* fmax/fmin family with quiet and signaling NaN arguments: a quiet NaN gives
 * the other operand silently, a signaling one poisons the result (fmax...) or
 * raises FE_INVALID (fmaximum_num...), fmaximum/fminimum propagate. fl raised
 * FE_INVALID for quiet NaNs and returned the number for signaling ones. */
static void min_max(void) {
    static const char *dnames[] = {"fmax", "fmin", "fmaxmag", "fminmag", "fmaximum_num",
                                   "fminimum_num", "fmaximum", "fminimum", 0};
    double q = __builtin_nan(""), sn = __builtin_nans("");
    float qf = __builtin_nanf(""), snf = __builtin_nansf("");
    for (const char **n = dnames; *n; n++) {
        double (*d)(double, double) = (double (*)(double, double))dlsym(RTLD_DEFAULT, *n);
        char fname[32];
        snprintf(fname, sizeof fname, "%sf", *n);
        float (*f)(float, float) = (float (*)(float, float))dlsym(RTLD_DEFAULT, fname);
        if (!d || !f) {
            continue;
        }
        double din[][2] = {{q, 1}, {1, q}, {sn, 1}, {1, sn}, {sn, q}, {-0.0, 0.0}};
        float fin[][2] = {{qf, 1}, {1, qf}, {snf, 1}, {1, snf}, {snf, qf}, {-0.0f, 0.0f}};
        printf("%-13s", *n);
        for (unsigned k = 0; k < 6; k++) {
            uint64_t b;
            feclearexcept(FE_ALL_EXCEPT);
            double r = d(din[k][0], din[k][1]);
            int inv = fetestexcept(FE_INVALID) != 0;
            memcpy(&b, &r, sizeof b);
            printf(" %016llx%s", (unsigned long long)b, inv ? "!" : " ");
        }
        printf(" |");
        for (unsigned k = 0; k < 6; k++) {
            uint32_t b;
            feclearexcept(FE_ALL_EXCEPT);
            float r = f(fin[k][0], fin[k][1]);
            int inv = fetestexcept(FE_INVALID) != 0;
            memcpy(&b, &r, sizeof b);
            printf(" %08x%s", (unsigned)b, inv ? "!" : " ");
        }
        printf("\n");
    }
}

/* _LIB_VERSION: glibc's compat data symbol is 2 (_POSIX_) and writable;
 * legacy programs assign _LIB_VERSION = _IEEE_ (-1). fl exported a read-only
 * 0, so the assignment faulted. */
static void lib_version(void) {
    int *p = (int *)dlsym(RTLD_DEFAULT, "_LIB_VERSION");
    if (!p) {
        p = (int *)dlvsym(dlopen("libm.so.6", RTLD_NOW), "_LIB_VERSION", "GLIBC_2.2.5");
    }
    if (!p) {
        printf("_LIB_VERSION missing\n");
        return;
    }
    printf("_LIB_VERSION %d", *p);
    *p = -1;
    printf(" -> %d\n", *p);
    *p = 2;
}

/* exp10/exp10f range edges: value bits, errno and FE_OVERFLOW/UNDERFLOW/INEXACT.
 * fl raised FE_OVERFLOW for exp10(-DBL_MAX) (x*ln10 overflowed before the
 * underflow path), raised no FE_INEXACT for exact powers (glibc does), and
 * left errno alone for exp10f results that round up to 2^-149. */
static void exp10_range(void) {
    static const double dins[] = {-DBL_MAX, -1e300, -1e20, -400, -323.5, -323.3, -308.5,
                                  308.25, 308.26, 1e20, DBL_MAX, 0, 1, 2, 3, 22, -1, 23};
    static const float fins[] = {-FLT_MAX, -1e30f, -46, -45.5f, -44.9f, -0x1.66d3eap+5f,
                                 -0x1.66d3e8p+5f, -37.9f, 38.5f, 38.53f, 1e30f, FLT_MAX, 0, 1,
                                 10, -1};
    for (unsigned i = 0; i < sizeof dins / sizeof *dins; i++) {
        uint64_t b;
        feclearexcept(FE_ALL_EXCEPT);
        errno = 0;
        double r = exp10(dins[i]);
        int e = errno, fe = fetestexcept(FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT);
        memcpy(&b, &r, sizeof b);
        printf("exp10  %a %016llx errno=%d O%d U%d I%d\n", dins[i], (unsigned long long)b, e,
               !!(fe & FE_OVERFLOW), !!(fe & FE_UNDERFLOW), !!(fe & FE_INEXACT));
    }
    for (unsigned i = 0; i < sizeof fins / sizeof *fins; i++) {
        uint32_t b;
        feclearexcept(FE_ALL_EXCEPT);
        errno = 0;
        float r = exp10f(fins[i]);
        int e = errno, fe = fetestexcept(FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT);
        memcpy(&b, &r, sizeof b);
        printf("exp10f %a %08x errno=%d O%d U%d I%d\n", (double)fins[i], (unsigned)b, e,
               !!(fe & FE_OVERFLOW), !!(fe & FE_UNDERFLOW), !!(fe & FE_INEXACT));
    }
}

/* A separate mode checks errno as well as the domain/pole result class and
 * exception flags. Verify both providers before collecting observations: a
 * passing host fallback must not qualify an interposed implementation. */
static int same_provider(void *address, const char *expected) {
    Dl_info info;
    struct stat actual_stat, expected_stat;
    if (!address || !dladdr(address, &info) || !info.dli_fname ||
        stat(info.dli_fname, &actual_stat) || stat(expected, &expected_stat) ||
        actual_stat.st_dev != expected_stat.st_dev ||
        actual_stat.st_ino != expected_stat.st_ino) {
        fprintf(stderr, "domain-errno: wrong or missing provider: %s\n", expected);
        return 0;
    }
    return 1;
}

static int domain_errno(const char *math_provider, const char *errno_provider) {
    static const char *functions[] = {
        "acos", "asin", "acosh", "atanh", "log", "log2", "log10", "log1p"
    };
    static const uint64_t inputs64[] = {
        0x7ff0000000000000ull, 0xfff0000000000000ull,
        0x7ff8000000000123ull, 0xfff8000000000123ull,
        0x7ff4000000000123ull, 0xfff4000000000123ull,
        0x0000000000000000ull, 0x8000000000000000ull,
        0x3ff0000000000000ull, 0xbff0000000000000ull,
        0x4000000000000000ull, 0xc000000000000000ull,
        0x3fe0000000000000ull, 0xbfe0000000000000ull
    };
    static const uint32_t inputs32[] = {
        0x7f800000u, 0xff800000u, 0x7fc00123u, 0xffc00123u,
        0x7fa00123u, 0xffa00123u, 0x00000000u, 0x80000000u,
        0x3f800000u, 0xbf800000u, 0x40000000u, 0xc0000000u,
        0x3f000000u, 0xbf000000u
    };
    static const int initial_errnos[] = {0, E2BIG};
    if (!dlopen("libm.so.6", RTLD_NOW | RTLD_GLOBAL)) {
        fprintf(stderr, "domain-errno: cannot load host libm\n");
        return 90;
    }
    if (!same_provider(dlsym(RTLD_DEFAULT, "__errno_location"), errno_provider)) {
        return 91;
    }
    for (unsigned n = 0; n < sizeof functions / sizeof *functions; ++n) {
        char float_name[32];
        snprintf(float_name, sizeof float_name, "%sf", functions[n]);
        double (*df)(double) = (double (*)(double))dlsym(RTLD_DEFAULT, functions[n]);
        float (*ff)(float) = (float (*)(float))dlsym(RTLD_DEFAULT, float_name);
        if (!same_provider((void *)df, math_provider) ||
            !same_provider((void *)ff, math_provider)) {
            return 91;
        }
        for (unsigned e = 0; e < sizeof initial_errnos / sizeof *initial_errnos; ++e) {
            for (unsigned i = 0; i < sizeof inputs64 / sizeof *inputs64; ++i) {
                double x;
                uint64_t bits;
                memcpy(&x, &inputs64[i], sizeof x);
                feclearexcept(FE_ALL_EXCEPT);
                errno = initial_errnos[e];
                double result = df(x);
                int observed_errno = errno;
                int flags = fetestexcept(FE_INVALID | FE_DIVBYZERO);
                memcpy(&bits, &result, sizeof bits);
                uint64_t magnitude = bits & 0x7fffffffffffffffull;
                int kind = magnitude > 0x7ff0000000000000ull ? 3 :
                           magnitude == 0x7ff0000000000000ull ? 2 :
                           magnitude == 0 ? 1 : 0;
                printf("errno64 %-8s %016llx initial=%d result=%d errno=%d invalid=%d pole=%d\n",
                       functions[n], (unsigned long long)inputs64[i], initial_errnos[e],
                       kind, observed_errno, !!(flags & FE_INVALID), !!(flags & FE_DIVBYZERO));
            }
            for (unsigned i = 0; i < sizeof inputs32 / sizeof *inputs32; ++i) {
                float x;
                uint32_t bits;
                memcpy(&x, &inputs32[i], sizeof x);
                feclearexcept(FE_ALL_EXCEPT);
                errno = initial_errnos[e];
                float result = ff(x);
                int observed_errno = errno;
                int flags = fetestexcept(FE_INVALID | FE_DIVBYZERO);
                memcpy(&bits, &result, sizeof bits);
                uint32_t magnitude = bits & 0x7fffffffu;
                int kind = magnitude > 0x7f800000u ? 3 :
                           magnitude == 0x7f800000u ? 2 :
                           magnitude == 0 ? 1 : 0;
                printf("errno32 %-8s %08x initial=%d result=%d errno=%d invalid=%d pole=%d\n",
                       float_name, inputs32[i], initial_errnos[e], kind, observed_errno,
                       !!(flags & FE_INVALID), !!(flags & FE_DIVBYZERO));
            }
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "--domain-errno") == 0) {
        return domain_errno(argv[2], argv[3]);
    }
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--domain-errno MATH_PROVIDER ERRNO_PROVIDER]\n", argv[0]);
        return 2;
    }
    doubles();
    floats();
    min_max();
    lib_version();
    exp10_range();
    return 0;
}
