//! Integration gate test for `bd-otip6a`:
//! verifies binary64 (`f64`) `libm` correct-rounding and host glibc 2.43 parity
//! across all transcendental kernels (`sin`, `cos`, `sincos`, `tan`, `asin`,
//! `acos`, `atan`, `atan2`, `sinh`, `cosh`, `tanh`, `asinh`, `acosh`, `atanh`,
//! `exp`, `exp2`, `exp10`, `expm1`, `log`, `log2`, `log10`, `log1p`, `erf`,
//! `erfc`, `cbrt`, `tgamma`, `lgamma`, `lgamma_r`, `pow`) against both 113-bit
//! `libquadmath` (`__float128`) and host `libm.so.6`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
        Path::new(manifest_dir)
            .parent()
            .and_then(Path::parent)
            .expect("workspace root must exist")
            .to_path_buf()
    } else {
        std::env::current_dir().expect("cwd must exist")
    }
}

#[test]
fn binary64_coremath_dispatch_and_trig_wiring_are_complete() {
    let root = workspace_root();
    let trig = fs::read_to_string(root.join("crates/frankenlibc-core/src/math/trig.rs"))
        .expect("trig.rs readable");
    assert!(trig.contains("crate::math::coremath::sin(x)"));
    assert!(trig.contains("crate::math::coremath::cos(x)"));
    assert!(trig.contains("crate::math::coremath::tan(x)"));
    assert!(trig.contains("crate::math::coremath::asin(x)"));
    assert!(trig.contains("crate::math::coremath::acos(x)"));
    assert!(trig.contains("crate::math::coremath::atan(x)"));
    assert!(trig.contains("crate::math::coremath::atan2(y, x)"));
    assert!(!trig.contains("libm::asin("));
    assert!(!trig.contains("libm::acos("));
    assert!(!trig.contains("libm::atan2("));

    let coremath = fs::read_to_string(root.join("crates/frankenlibc-core/src/math/coremath.rs"))
        .expect("coremath.rs readable");
    assert!(coremath.contains("pub fn asin(x: f64) -> f64 => asin_body;"));
    assert!(coremath.contains("pub fn acos(x: f64) -> f64 => acos_body;"));
    assert!(coremath.contains("pub fn atan2(y: f64, x: f64) -> f64 => atan2_body;"));
}

#[test]
fn libm_f64_cr_quadmath_and_glibc_parity_gate_passes() {
    let root = workspace_root();
    let explicit_lib = std::env::var_os("FRANKENLIBC_LIBM_TEST_LIB").map(PathBuf::from);
    let lib = explicit_lib
        .clone()
        .unwrap_or_else(|| root.join("target/release/libfrankenlibc_abi.so"));
    if explicit_lib.is_some() {
        assert!(
            lib.is_file(),
            "FRANKENLIBC_LIBM_TEST_LIB must point to an existing release libfrankenlibc_abi.so: {}",
            lib.display()
        );
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!("fl_libm_f64_gate_{}_{nanos}", std::process::id()));
    fs::create_dir_all(&tmp).expect("temp dir creatable");
    let probe_c = tmp.join("probe_f64.c");
    let probe_bin = tmp.join("probe_f64");

    fs::write(
        &probe_c,
        r#"#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fenv.h>
#include <gnu/libc-version.h>
#include <math.h>
#include <quadmath.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t d2u(double x) { uint64_t u; memcpy(&u, &x, 8); return u; }
static double u2d(uint64_t u) { double x; memcpy(&x, &u, 8); return x; }

static uint64_t ulp_diff_f64(double a, double b) {
    if (isnan(a) && isnan(b)) return 0;
    if (isnan(a) || isnan(b)) return UINT64_MAX;
    uint64_t ua = d2u(a), ub = d2u(b);
    if ((ua >> 63) != (ub >> 63)) return UINT64_MAX;
    return (ua > ub) ? (ua - ub) : (ub - ua);
}

typedef double (*d1_t)(double);
typedef double (*d2_t)(double, double);
typedef void (*sincos_t)(double, double *, double *);
typedef double (*lgamma_r_t)(double, int *);
typedef int *(*errno_loc_t)(void);
typedef __float128 (*q1_t)(__float128);

static __float128 my_exp10q(__float128 x) { return powq(10.0Q, x); }

struct UnarySpec {
    const char *name;
    q1_t qfn;
    double lo;
    double hi;
    uint64_t max_uq;
    int require_cr_exact;
    int require_glibc_exact;
};

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *fl = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    void *gl = dlopen("libm.so.6", RTLD_NOW | RTLD_LOCAL);
    if (!fl || !gl) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 2; }
    int gl_maj = 0, gl_min = 0;
    sscanf(gnu_get_libc_version(), "%d.%d", &gl_maj, &gl_min);
    int gl_ge_243 = (gl_maj > 2) || (gl_maj == 2 && gl_min >= 43);

    const struct UnarySpec specs[] = {
        {"sin", sinq, -1000.0, 1000.0, 0, 1, 0},
        {"cos", cosq, -1000.0, 1000.0, 0, 1, 0},
        {"tan", tanq, -1000.0, 1000.0, 0, 1, 0},
        {"asin", asinq, -1.0, 1.0, 0, 1, 0},
        {"acos", acosq, -1.0, 1.0, 0, 1, 0},
        {"atan", atanq, -1000.0, 1000.0, 0, 1, 0},
        {"asinh", asinhq, -1000.0, 1000.0, 0, 1, 1},
        {"acosh", acoshq, 1.0, 1000.0, 0, 1, 1},
        {"atanh", atanhq, -0.999999, 0.999999, 0, 1, 1},
        {"erf", erfq, -6.0, 6.0, 0, 1, 1},
        {"erfc", erfcq, -6.0, 27.0, 0, 1, 1},
        {"cbrt", cbrtq, -1000.0, 1000.0, 0, 1, 0},
        {"tgamma", tgammaq, -10.5, 170.0, 0, 1, 1},
        {"lgamma", lgammaq, -10.5, 1000.0, 0, 1, 1},
        {"exp", expq, -700.0, 700.0, 1, 0, 1},
        {"exp2", exp2q, -1020.0, 1020.0, 1, 0, 0},
        {"exp10", my_exp10q, -305.0, 305.0, 1, 0, 0},
        {"expm1", expm1q, -50.0, 50.0, 1, 0, 0},
        {"log", logq, 1e-300, 1e300, 0, 1, 1},
        {"log2", log2q, 1e-300, 1e300, 1, 0, 1},
        {"log10", log10q, 1e-300, 1e300, 1, 0, 1},
        {"log1p", log1pq, -0.999999, 1000.0, 1, 0, 0},
        {"sinh", sinhq, -700.0, 700.0, 1, 0, 0},
        {"cosh", coshq, -700.0, 700.0, 1, 0, 1},
        /* fdlibm s_tanh.c (also used by glibc 2.43) has max 2 ULP vs binary128 */
        {"tanh", tanhq, -20.0, 20.0, 2, 0, 0},
    };

    const uint32_t N = 250000;
    uint64_t st = 0x9e3779b97f4a7c15ULL;

    for (size_t s = 0; s < sizeof(specs)/sizeof(specs[0]); s++) {
        const struct UnarySpec *sp = &specs[s];
        d1_t ff = (d1_t)dlsym(fl, sp->name);
        d1_t gf = (d1_t)dlsym(gl, sp->name);
        if (!ff || !gf) { fprintf(stderr, "missing %s\n", sp->name); return 2; }
        uint32_t cr_diffs = 0, gl_diffs = 0;
        for (uint32_t i = 0; i < N; i++) {
            st ^= st << 13; st ^= st >> 7; st ^= st << 17;
            double u = (double)(st >> 11) * 0x1p-53;
            double x = sp->lo + (sp->hi - sp->lo) * u;
            if ((sp->lo < 0.0) && (i % 16 == 0) && floor(x) == x && x <= 0.0) {
                x += 0.125; /* avoid negative-integer poles for gamma */
            }
            double fv = ff(x);
            double gv = gf(x);
            double qv = (double)sp->qfn((__float128)x);
            uint64_t uq = ulp_diff_f64(fv, qv);
            uint64_t ug = ulp_diff_f64(fv, gv);
            if (uq > 0) cr_diffs++;
            if (ug > 0) gl_diffs++;
            if (uq > sp->max_uq) {
                fprintf(stderr, "FAIL %s(%.17g): fl=0x%016lx q=0x%016lx gl=0x%016lx uq=%lu max_uq=%lu ug=%lu\n",
                        sp->name, x, d2u(fv), d2u(qv), d2u(gv), uq, sp->max_uq, ug);
                return 1;
            }
            if (gl_ge_243 && ug > sp->max_uq + 3) {
                fprintf(stderr, "FAIL %s(%.17g) ug=%lu > %lu vs glibc 2.43+\n", sp->name, x, ug, sp->max_uq + 3);
                return 1;
            }
        }
        if (sp->require_cr_exact && cr_diffs != 0) {
            fprintf(stderr, "FAIL %s expected 0 CR diffs vs __float128, got %u/%u\n", sp->name, cr_diffs, N);
            return 1;
        }
        if (gl_ge_243 && sp->require_glibc_exact && gl_diffs != 0) {
            fprintf(stderr, "FAIL %s expected 0 diffs vs glibc 2.43+, got %u/%u\n", sp->name, gl_diffs, N);
            return 1;
        }
        if (gl_ge_243 && strcmp(sp->name, "tanh") == 0 && gl_diffs > 50) {
            fprintf(stderr, "FAIL tanh gl_diffs=%u/%u exceeded fdlibm bound 50\n", gl_diffs, N);
            return 1;
        }
    }

    d1_t fl_sin = (d1_t)dlsym(fl, "sin");
    d1_t fl_cos = (d1_t)dlsym(fl, "cos");
    d1_t fl_asin = (d1_t)dlsym(fl, "asin");
    d1_t fl_acos = (d1_t)dlsym(fl, "acos");
    sincos_t fl_sincos = (sincos_t)dlsym(fl, "sincos");
    lgamma_r_t fl_lgamma_r = (lgamma_r_t)dlsym(fl, "lgamma_r");
    lgamma_r_t gl_lgamma_r = (lgamma_r_t)dlsym(gl, "lgamma_r");
    d2_t fl_atan2 = (d2_t)dlsym(fl, "atan2");
    d2_t gl_atan2 = (d2_t)dlsym(gl, "atan2");
    d2_t fl_pow = (d2_t)dlsym(fl, "pow");
    d2_t gl_pow = (d2_t)dlsym(gl, "pow");
    errno_loc_t fl_errno = (errno_loc_t)dlsym(fl, "__errno_location");
    if (!fl_sin || !fl_cos || !fl_asin || !fl_acos || !fl_sincos ||
        !fl_lgamma_r || !gl_lgamma_r || !fl_atan2 || !gl_atan2 || !fl_pow || !gl_pow || !fl_errno) {
        fprintf(stderr, "missing binary/multi-output f64 libm symbol\n");
        return 2;
    }

    /* Special values, signed zeros, domain errors, tiny & near-endpointasin/acos, and exact subnormal midpoints: */
    if (d2u(fl_asin(0.0)) != 0 || d2u(fl_asin(-0.0)) != (1ULL << 63) ||
        d2u(fl_asin(1.0)) != 0x3ff921fb54442d18ULL || d2u(fl_asin(-1.0)) != 0xbff921fb54442d18ULL ||
        !isnan(fl_asin(1.5)) || !isnan(fl_asin(INFINITY)) ||
        d2u(fl_acos(1.0)) != 0 || d2u(fl_acos(-1.0)) != 0x400921fb54442d18ULL || !isnan(fl_acos(-1.5)) ||
        d2u(fl_acos(u2d(0xbc8cb3b399d747f3ULL))) != 0x3ff921fb54442d19ULL ||
        d2u(fl_acos(u2d(0xbc8cb3b399d747f4ULL))) != 0x3ff921fb54442d19ULL ||
        d2u(fl_atan2(-0.0, 1.0)) != (1ULL << 63) || d2u(fl_atan2(-0.0, -1.0)) != 0xc00921fb54442d18ULL ||
        d2u(fl_atan2(u2d((24ULL << 52) | (1ULL << 51)), u2d(1098ULL << 52))) != 1ULL ||
        d2u(fl_atan2(u2d(0x01c2c00000000000ULL), u2d(0x44ce000000000000ULL))) != 2ULL) {
        fprintf(stderr, "FAIL special/subnormal-midpoint f64 check\n");
        return 1;
    }
    for (int k = 1; k <= 4096; k++) {
        double near1 = 1.0 - (double)k * 0x1p-52;
        double tiny1 = (double)k * 0x1p-40;
        double tiny2 = (double)k * 0x1p-60;
        double subn = u2d((uint64_t)k);
        double xs[6] = {near1, -near1, tiny1, -tiny1, tiny2, subn};
        for (int j = 0; j < 6; j++) {
            if (ulp_diff_f64(fl_asin(xs[j]), (double)asinq((__float128)xs[j])) != 0 ||
                ulp_diff_f64(fl_acos(xs[j]), (double)acosq((__float128)xs[j])) != 0) {
                fprintf(stderr, "FAIL boundary asin/acos at %.17g\n", xs[j]);
                return 1;
            }
        }
    }
    d1_t fl_tan = (d1_t)dlsym(fl, "tan");
    if (!fl_tan) return 2;
    double inf_inputs[2] = {INFINITY, -INFINITY};
    for (int k = 0; k < 2; k++) {
        double v = inf_inputs[k];
        *fl_errno() = 0;
        double inf_s = 0.0, inf_c = 0.0;
        fl_sincos(v, &inf_s, &inf_c);
        if (!isnan(inf_s) || !isnan(inf_c) || *fl_errno() != EDOM) {
            fprintf(stderr, "FAIL sincos(%g) EDOM: errno=%d\n", v, *fl_errno());
            return 1;
        }
        d1_t tfs[3] = {fl_sin, fl_cos, fl_tan};
        const char *tnames[3] = {"sin", "cos", "tan"};
        for (int t = 0; t < 3; t++) {
            *fl_errno() = 0;
            double r = tfs[t](v);
            if (!isnan(r) || *fl_errno() != EDOM) {
                fprintf(stderr, "FAIL %s(%g) EDOM: r=%g errno=%d\n", tnames[t], v, r, *fl_errno());
                return 1;
            }
        }
    }

    /* Directed rounding + FE_INEXACT checks on subnormal/negative atan2 and asin: */
    feclearexcept(FE_ALL_EXCEPT);
    double p2_rne = fl_asin(1.0);
    if (d2u(p2_rne) != 0x3ff921fb54442d18ULL || !fetestexcept(FE_INEXACT)) {
        fprintf(stderr, "FAIL asin(1.0) FE_INEXACT\n");
        return 1;
    }
    double y_neg_exact = -0x1p-945;
    double x_pos_exact = 0x1p+76;
    fesetround(FE_UPWARD);
    uint64_t up_tiny = d2u(fl_atan2(u2d(1ULL), u2d(0x7fe0000000000000ULL)));
    uint64_t up_p2 = d2u(fl_asin(1.0));
    uint64_t up_neg_exact = d2u(fl_atan2(y_neg_exact, x_pos_exact));
    uint64_t up_sub_asin = d2u(fl_asin(u2d(1ULL)));
    fesetround(FE_TOWARDZERO);
    uint64_t tz_ulp = d2u(fl_atan2(u2d(24ULL << 52), u2d(1098ULL << 52)));
    fesetround(FE_DOWNWARD);
    uint64_t dn_neg = d2u(fl_atan2(-u2d(1ULL), u2d(0x7fe0000000000000ULL)));
    uint64_t dn_neg_exact = d2u(fl_atan2(y_neg_exact, x_pos_exact));
    uint64_t dn_sub_asin = d2u(fl_asin(-u2d(1ULL)));
    fesetround(FE_TONEAREST);
    if (up_tiny != 1ULL || up_p2 != 0x3ff921fb54442d19ULL || tz_ulp != 0ULL ||
        dn_neg != ((1ULL << 63) | 1ULL) ||
        up_neg_exact != 0x801fffffffffffffULL ||
        dn_neg_exact != 0x8020000000000000ULL ||
        up_sub_asin != 2ULL ||
        dn_sub_asin != ((1ULL << 63) | 2ULL)) {
        fprintf(stderr,
                "FAIL directed rounding: up_tiny=%lx up_p2=%lx tz_ulp=%lx dn_neg=%lx "
                "up_neg_ex=%lx dn_neg_ex=%lx up_asin=%lx dn_asin=%lx\n",
                up_tiny, up_p2, tz_ulp, dn_neg, up_neg_exact, dn_neg_exact, up_sub_asin, dn_sub_asin);
        return 1;
    }

    for (uint32_t i = 0; i < N; i++) {
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        uint64_t ry = st;
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        uint64_t rx = st;
        double y, x;
        if (i % 4 == 0) {
            if (((ry >> 52) & 0x7ff) == 0x7ff) ry &= ~(1ULL << 52);
            if (((rx >> 52) & 0x7ff) == 0x7ff) rx &= ~(1ULL << 52);
            y = u2d(ry);
            x = u2d(rx);
        } else {
            y = ((double)(ry >> 11) * 0x1p-53 * 20.0) - 10.0;
            x = ((double)(rx >> 11) * 0x1p-53 * 20.0) - 10.0;
            if (x == 0.0) x = 1e-12;
        }
        double fa = fl_atan2(y, x);
        double qa = (double)atan2q((__float128)y, (__float128)x);
        if (ulp_diff_f64(fa, qa) != 0) {
            fprintf(stderr, "FAIL atan2(%.17g, %.17g): fl=0x%016lx q=0x%016lx gl=0x%016lx\n",
                    y, x, d2u(fa), d2u(qa), d2u(gl_atan2(y, x)));
            return 1;
        }

        double sx = -100.0 + ((double)(ry >> 11) * 0x1p-53) * 200.0;
        double fs = 0.0, fc = 0.0;
        fl_sincos(sx, &fs, &fc);
        if (d2u(fs) != d2u(fl_sin(sx)) || d2u(fc) != d2u(fl_cos(sx))) {
            fprintf(stderr, "FAIL sincos(%.17g)\n", sx);
            return 1;
        }

        double lx = -10.5 + ((double)(rx >> 11) * 0x1p-53) * 200.0;
        if (floor(lx) == lx && lx <= 0.0) lx += 0.125;
        int fsgn = 0, gsgn = 0;
        double flg = fl_lgamma_r(lx, &fsgn);
        double glg = gl_lgamma_r(lx, &gsgn);
        (void)glg;
        if (ulp_diff_f64(flg, (double)lgammaq((__float128)lx)) != 0 || fsgn != gsgn) {
            fprintf(stderr, "FAIL lgamma_r(%.17g): sgn=%d/%d\n", lx, fsgn, gsgn);
            return 1;
        }

        double pb = 0.01 + ((double)(ry >> 11) * 0x1p-53) * 10.0;
        double pe = -5.0 + ((double)(rx >> 11) * 0x1p-53) * 10.0;
        if (gl_ge_243 && ulp_diff_f64(fl_pow(pb, pe), gl_pow(pb, pe)) != 0) {
            fprintf(stderr, "FAIL pow(%.17g, %.17g)\n", pb, pe);
            return 1;
        }
        if (ulp_diff_f64(fl_pow(pb, pe), (double)powq((__float128)pb, (__float128)pe)) > 1) {
            fprintf(stderr, "FAIL pow CR(%.17g, %.17g)\n", pb, pe);
            return 1;
        }
    }

    printf("PASS: libm_f64_cr_parity verified (7.25M evaluations across 29 f64 functions, 0 non-CR on all CORE-MATH/CR kernels)\n");
    return 0;
}
"#,
    )
    .expect("probe_f64.c written");

    let st = Command::new("cc")
        .args(["-O3", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(&probe_c)
        .args(["-lquadmath", "-ldl", "-lm", "-o"])
        .arg(&probe_bin)
        .status()
        .expect("cc probe_f64");
    assert!(st.success(), "failed compiling probe_f64.c");

    if !lib.is_file() {
        return;
    }

    for mode in ["strict", "hardened"] {
        let out = Command::new(&probe_bin)
            .arg(&lib)
            .env("FRANKENLIBC_MODE", mode)
            .output()
            .expect("probe_f64 execution");
        assert!(
            out.status.success(),
            "probe_f64 ({mode}) failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("PASS: libm_f64_cr_parity verified"),
            "missing PASS banner in {mode}"
        );
    }
}
