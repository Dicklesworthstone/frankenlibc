/* The long double (x87 80-bit) math ABI: every argument/return shape.
 *
 * On x86_64 a long double argument lives in a 16-byte stack slot and the
 * result comes back in ST(0). fl exported these functions with double
 * signatures, so callers got garbage AND an x87 stack underflow that turned
 * every later long double operation into NaN (gawk's persistent heap crashed
 * sizing its free lists with floorl). Exact functions print in hex; the
 * transcendental ones to 12 significant digits, which any 64-bit-mantissa
 * result agrees on. Output matches glibc.
 */
#define _GNU_SOURCE
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static const long double xs[] = {0.0L, -0.0L, 0.75L, -2.5L, 3.141592653589793238L,
                                 1e30L, -1e-30L, 123456789.987654321L, 0x1.fffffffffffffffep+63L};
#define N (sizeof xs / sizeof *xs)

int main(void) {
    for (unsigned i = 0; i < N; i++) {
        long double x = xs[i];
        int e = 0, q = 0;
        long double ip = 0;
        printf("x=%La floor=%La ceil=%La trunc=%La round=%La rint=%La fabs=%La\n", x, floorl(x),
               ceill(x), truncl(x), roundl(x), rintl(x), fabsl(x));
        long double m = frexpl(x, &e);
        long double fr = modfl(x, &ip);
        printf("  frexp=%La,%d ldexp=%La scalbn=%La modf=%La,%La ilogb=%d logb=%La\n", m, e,
               ldexpl(x, 7), scalbnl(x, -3), fr, ip, x != 0 ? ilogbl(x) : 0,
               x != 0 ? logbl(x) : 0.0L);
        long double r = remquol(x, 0.7L, &q);
        printf("  fmod=%La remainder=%La remquo=%La,%d copysign=%La fmax=%La fmin=%La fdim=%La\n",
               fmodl(x, 0.7L), remainderl(x, 0.7L), r, q, copysignl(1.5L, x), fmaxl(x, 1.0L),
               fminl(x, 1.0L), fdiml(x, 1.0L));
        printf("  nextafter=%La nextup=%La nextdown=%La fma=%La sqrt|x|=%La\n",
               nextafterl(x, 0.0L), nextupl(x), nextdownl(x), fmal(x, 2.0L, 0.25L),
               sqrtl(fabsl(x)));
        printf("  isnan=%d isinf=%d finite=%d signbit=%d fpclassify=%d lrint=%ld llround=%lld\n",
               isnan(x), isinf(x), isfinite(x), signbit(x) != 0, fpclassify(x),
               fabsl(x) < 1e15L ? lrintl(x) : 0L, fabsl(x) < 1e15L ? llroundl(x) : 0LL);
        long double s = 0, c = 0;
        sincosl(x, &s, &c);
        printf("  sin=%.12Lg cos=%.12Lg sincos=%.12Lg,%.12Lg tan=%.12Lg atan=%.12Lg atan2=%.12Lg\n",
               sinl(x), cosl(x), s, c, tanl(x), atanl(x), atan2l(x, 2.0L));
        printf("  exp=%.12Lg expm1=%.12Lg log|x|=%.12Lg log1p=%.12Lg cbrt=%.12Lg pow=%.12Lg "
               "hypot=%.12Lg\n",
               fabsl(x) < 100 ? expl(x) : 0.0L, fabsl(x) < 100 ? expm1l(x) : 0.0L,
               x != 0 ? logl(fabsl(x)) : 0.0L, log1pl(fabsl(x)), cbrtl(x),
               powl(fabsl(x), 0.5L), hypotl(x, 3.0L));
        printf("  sinh=%.12Lg tanh=%.12Lg erf=%.12Lg lgamma=%.12Lg j0=%.12Lg\n",
               fabsl(x) < 100 ? sinhl(x) : 0.0L, tanhl(x), erfl(x),
               x > 0 && x < 1e6 ? lgammal(x) : 0.0L, fabsl(x) < 1e6 ? j0l(x) : 0.0L);
    }
    printf("nan=%d %d inf=%d\n", isnan(nanl("")), isnan(nanl("0x5")), isinf(-HUGE_VALL));
    /* Narrowing, fromfp, pointer-based and _Float64x shapes. */
    printf("fadd=%a dmul=%a ddiv=%a fsqrt=%a dfma=%a\n", faddl(1.5L, 0x1p-30L),
           dmull(3.0L, 0.1L), ddivl(1.0L, 3.0L), fsqrtl(2.0L), dfmal(1.5L, 2.0L, 0.125L));
    long double p = 1.0L, q2 = -0.0L, pl = 0, res = 0;
    long double nan_payload = nanl("0x2a");
    int set_rc = setpayloadl(&res, 42.0L);
    long double got = getpayloadl(&res);
    int bad_rc = setpayloadl(&res, 1.5L);
    int canon_rc = canonicalizel(&pl, &p);
    printf("totalorder=%d %d payload=%La setpayload=%d,%La bad=%d canonicalize=%d,%La\n",
           totalorderl(&q2, &p), totalorderl(&p, &q2), getpayloadl(&nan_payload), set_rc, got,
           bad_rc, canon_rc, pl);
    char sbuf[64];
    int sn = strfroml(sbuf, sizeof sbuf, "%.25g", 3.141592653589793238462643L);
    printf("strfroml=%d:%s\n", sn, sbuf);
    _Float64x fx = 2.0F64x;
    printf("f64x: sqrt=%La exp2=%La ldexp=%La\n", (long double)sqrtf64x(fx),
           (long double)exp2f64x(fx), (long double)ldexpf64x(fx, 3));
    /* The x87 stack must still be usable after all of the above. */
    volatile long double a = 1.25L, b = 2.5L;
    printf("after: %La\n", a + b);
    return 0;
}
