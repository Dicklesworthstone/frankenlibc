/* fixture_math.c — math conformance smoke fixture (bd-15n.2)
 * Exit 0 = PASS, nonzero = FAIL with diagnostics.
 */
#include <math.h>
#include <stdio.h>

static int approx(double a, double b, double tol) {
    return fabs(a - b) <= tol;
}

static int test_trig(void) {
    if (!approx(sin(0.0), 0.0, 1e-12)) {
        fprintf(stderr, "FAIL: sin(0)\n");
        return 1;
    }
    if (!approx(cos(0.0), 1.0, 1e-12)) {
        fprintf(stderr, "FAIL: cos(0)\n");
        return 1;
    }
    return 0;
}

static int test_exp_log(void) {
    double e = exp(1.0);
    if (!approx(log(e), 1.0, 1e-12)) {
        fprintf(stderr, "FAIL: log(exp(1))\n");
        return 1;
    }
    return 0;
}

static int test_rounding(void) {
    if (!approx(floor(2.75), 2.0, 1e-12)) {
        fprintf(stderr, "FAIL: floor(2.75)\n");
        return 1;
    }
    if (!approx(ceil(2.25), 3.0, 1e-12)) {
        fprintf(stderr, "FAIL: ceil(2.25)\n");
        return 1;
    }
    if (!approx(fmod(7.0, 2.0), 1.0, 1e-12)) {
        fprintf(stderr, "FAIL: fmod(7,2)\n");
        return 1;
    }
    return 0;
}

int main(void) {
    int fails = 0;
    fails += test_trig();
    fails += test_exp_log();
    fails += test_rounding();

    if (fails) {
        fprintf(stderr, "fixture_math: %d FAILED\n", fails);
        return 1;
    }
    printf("fixture_math: PASS (3 tests)\n");
    return 0;
}
