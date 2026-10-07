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
#include <math.h>
#include <fenv.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

int main(void) {
    doubles();
    floats();
    min_max();
    return 0;
}
