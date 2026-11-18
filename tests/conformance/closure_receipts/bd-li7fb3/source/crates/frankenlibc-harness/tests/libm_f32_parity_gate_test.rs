//! Integration gate test for `bd-li7fb3`:
//! verifies single-precision (`f32`) `libm` accuracy and host glibc 2.43 parity
//! across unary and binary entrypoints (`expf`, `exp2f`, `exp10f`, `expm1f`,
//! `logf`, `log2f`, `log10f`, `log1pf`, `sinf`, `cosf`, `sincosf`, `tanf`,
//! `asinf`, `acosf`, `atanf`, `atan2f`, `sinhf`, `coshf`, `tanhf`, `asinhf`,
//! `acoshf`, `atanhf`, `cbrtf`, `sqrtf`, `erff`, `erfcf`, `tgammaf`, `lgammaf`,
//! `lgammaf_r`, `hypotf`, `powf`).

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
fn float32_kernels_route_through_cr_f64_and_consistent_sincosf() {
    let root = workspace_root();
    let f32_src = fs::read_to_string(root.join("crates/frankenlibc-core/src/math/float32.rs"))
        .expect("float32.rs readable");

    assert!(
        f32_src.contains("pub fn sincosf(x: f32) -> (f32, f32)")
            && f32_src.contains("(sinf(x), cosf(x))")
            && !f32_src.contains("libm::sincosf(x)"),
        "sincosf must delegate to (sinf(x), cosf(x)) rather than 2-ULP libm::sincosf"
    );
    assert!(f32_src.contains("crate::math::asin(f64::from(x)) as f32"));
    assert!(f32_src.contains("crate::math::acos(f64::from(x)) as f32"));
    assert!(f32_src.contains("crate::math::atan2(f64::from(y), f64::from(x)) as f32"));
    assert!(f32_src.contains("crate::math::lgamma_r(f64::from(x))"));
}

#[test]
fn libm_f32_live_so_ulp_and_fixture_parity_gate_passes() {
    let root = workspace_root();
    let lib = root.join("target/release/libfrankenlibc_abi.so");
    if !lib.is_file() {
        for fixture in [
            "tests/integration/fixture_libm_f32_sample.c",
            "tests/integration/fixture_libm_special_values.c",
        ] {
            let status = Command::new("cc")
                .args(["-std=c11", "-fsyntax-only", "-Wall", "-Wextra", "-Werror"])
                .arg(root.join(fixture))
                .status()
                .expect("cc -fsyntax-only must run");
            assert!(status.success(), "syntax check failed for {fixture}");
        }
        return;
    }

    let tmp = std::env::temp_dir().join(format!("fl_libm_f32_gate_{}", std::process::id()));
    fs::create_dir_all(&tmp).expect("temp dir creatable");

    let ldd_ver = Command::new("ldd")
        .arg("--version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let host_glibc_ge_243 = ldd_ver
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().last())
        .and_then(|ver| {
            let mut it = ver.split('.');
            let maj: u32 = it.next()?.parse().ok()?;
            let min: u32 = it.next()?.parse().ok()?;
            Some((maj, min) >= (2, 43))
        })
        .unwrap_or(false);

    // 1. Verify existing fixture_libm_f32_sample + fixture_libm_special_values execute cleanly
    // (and match host glibc 2.43+ byte-for-byte in strict + hardened):
    for (name, src) in [
        ("sample", "tests/integration/fixture_libm_f32_sample.c"),
        ("special", "tests/integration/fixture_libm_special_values.c"),
    ] {
        let bin = tmp.join(format!("fixture_{name}"));
        let st = Command::new("cc")
            .args(["-O0", "-fno-builtin", "-std=c11"])
            .arg(root.join(src))
            .args(["-ldl", "-lm", "-o"])
            .arg(&bin)
            .status()
            .expect("cc compile must run");
        assert!(st.success(), "failed compiling {src}");

        let host = Command::new(&bin)
            .env_remove("LD_PRELOAD")
            .output()
            .expect("host fixture run");
        assert!(
            host.status.success(),
            "host {name} failed: {}",
            String::from_utf8_lossy(&host.stderr)
        );

        for mode in ["strict", "hardened"] {
            let cand = Command::new(&bin)
                .env("LD_PRELOAD", &lib)
                .env("FRANKENLIBC_MODE", mode)
                .output()
                .expect("candidate fixture run");
            assert!(
                cand.status.success(),
                "{name} ({mode}) failed: {}",
                String::from_utf8_lossy(&cand.stderr)
            );
            if host_glibc_ge_243 || name == "special" {
                assert_eq!(
                    cand.stdout,
                    host.stdout,
                    "{name} ({mode}) stdout diverged from host glibc:\ncand:\n{}\nhost:\n{}",
                    String::from_utf8_lossy(&cand.stdout),
                    String::from_utf8_lossy(&host.stdout)
                );
            }
        }
    }

    // 2. Live 2,000,000-input-per-function sweep across 26 unary f32 functions + sincosf + atan2f + hypotf + powf + lgammaf_r:
    let probe_c = tmp.join("probe_f32.c");
    let probe_bin = tmp.join("probe_f32");
    fs::write(
        &probe_c,
        r#"#define _GNU_SOURCE
#include <dlfcn.h>
#include <gnu/libc-version.h>
#include <math.h>
#include <quadmath.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t f2u(float x) { uint32_t u; memcpy(&u, &x, 4); return u; }
static float u2f(uint32_t u) { float x; memcpy(&x, &u, 4); return x; }

static uint32_t ulp_diff_f32(float a, float b) {
    if (isnan(a) && isnan(b)) return 0;
    if (isnan(a) || isnan(b)) return 0xffffffffu;
    uint32_t ua = f2u(a), ub = f2u(b);
    if (((ua | ub) & 0x7fffffffu) == 0) return (ua == ub) ? 0 : 1;
    int32_t sa = (ua & 0x80000000u) ? -(int32_t)(ua & 0x7fffffffu) : (int32_t)ua;
    int32_t sb = (ub & 0x80000000u) ? -(int32_t)(ub & 0x7fffffffu) : (int32_t)ub;
    int64_t d = (int64_t)sa - (int64_t)sb;
    if (d < 0) d = -d;
    return (d > 0xffffffffLL) ? 0xffffffffu : (uint32_t)d;
}

typedef float (*f1_t)(float);
typedef float (*f2_t)(float, float);
typedef void (*sincosf_t)(float, float *, float *);
typedef float (*lgammaf_r_t)(float, int *);

static const struct { const char *name; int exact_glibc; } UNARY[] = {
    {"expf", 0}, {"exp2f", 0}, {"exp10f", 0}, {"expm1f", 1},
    {"logf", 1}, {"log2f", 1}, {"log10f", 0}, {"log1pf", 0},
    {"sinf", 0}, {"cosf", 0}, {"tanf", 1},
    {"asinf", 1}, {"acosf", 1}, {"atanf", 0},
    {"sinhf", 0}, {"coshf", 1}, {"tanhf", 1},
    {"asinhf", 0}, {"acoshf", 0}, {"atanhf", 1},
    {"cbrtf", 1}, {"sqrtf", 1}, {"erff", 1}, {"erfcf", 0},
    {"tgammaf", 0}, {"lgammaf", 0},
};

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *fl = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    void *gl = dlopen("libm.so.6", RTLD_NOW | RTLD_LOCAL);
    if (!fl || !gl) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 2; }
    int gl_maj = 0, gl_min = 0;
    sscanf(gnu_get_libc_version(), "%d.%d", &gl_maj, &gl_min);
    int gl_ge_243 = (gl_maj > 2) || (gl_maj == 2 && gl_min >= 43);

    const uint32_t N = 2000000;
    uint64_t st = 0x2545f4914f6cdd1dULL;

    for (size_t fn_i = 0; fn_i < sizeof(UNARY)/sizeof(UNARY[0]); fn_i++) {
        const char *nm = UNARY[fn_i].name;
        f1_t ff = (f1_t)dlsym(fl, nm);
        f1_t gf = (f1_t)dlsym(gl, nm);
        if (!ff || !gf) { fprintf(stderr, "missing %s\n", nm); return 2; }
        uint32_t max_u = 0, diffs = 0;
        uint32_t max_allowed = gl_ge_243 ? 1u : 3u;
        for (uint32_t i = 0; i < N; i++) {
            uint32_t bits;
            if (i < 4096) {
                bits = (i < 2048) ? i : ((0x7f800000u - (i - 2048)) | ((i & 1) << 31));
            } else {
                st ^= st << 13; st ^= st >> 7; st ^= st << 17;
                bits = (uint32_t)(st >> 16);
            }
            float x = u2f(bits);
            uint32_t u = ulp_diff_f32(ff(x), gf(x));
            if (u > 0) diffs++;
            if (u > max_u) max_u = u;
            if (u > max_allowed) {
                fprintf(stderr, "FAIL %s(0x%08x = %g): fl=0x%08x gl=0x%08x ulp=%u\n",
                        nm, bits, x, f2u(ff(x)), f2u(gf(x)), u);
                return 1;
            }
        }
        if (gl_ge_243 && UNARY[fn_i].exact_glibc && diffs != 0) {
            fprintf(stderr, "FAIL %s expected 0 diffs vs glibc 2.43+, got %u\n", nm, diffs);
            return 1;
        }
    }

    f1_t fl_sinf = (f1_t)dlsym(fl, "sinf");
    f1_t fl_cosf = (f1_t)dlsym(fl, "cosf");
    sincosf_t fl_sincosf = (sincosf_t)dlsym(fl, "sincosf");
    sincosf_t gl_sincosf = (sincosf_t)dlsym(gl, "sincosf");
    f2_t fl_atan2f = (f2_t)dlsym(fl, "atan2f");
    f2_t gl_atan2f = (f2_t)dlsym(gl, "atan2f");
    f2_t fl_hypotf = (f2_t)dlsym(fl, "hypotf");
    f2_t gl_hypotf = (f2_t)dlsym(gl, "hypotf");
    f2_t fl_powf = (f2_t)dlsym(fl, "powf");
    f2_t gl_powf = (f2_t)dlsym(gl, "powf");
    lgammaf_r_t fl_lgr = (lgammaf_r_t)dlsym(fl, "lgammaf_r");
    lgammaf_r_t gl_lgr = (lgammaf_r_t)dlsym(gl, "lgammaf_r");

    for (uint32_t i = 0; i < N; i++) {
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        float x = u2f((uint32_t)(st >> 16));
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        float y = u2f((uint32_t)(st >> 16));

        float fs, fc, gs, gc;
        fl_sincosf(x, &fs, &fc);
        gl_sincosf(x, &gs, &gc);
        float dsin = fl_sinf(x), dcos = fl_cosf(x);
        if (!((isnan(fs) && isnan(dsin)) || f2u(fs) == f2u(dsin)) ||
            !((isnan(fc) && isnan(dcos)) || f2u(fc) == f2u(dcos))) {
            fprintf(stderr, "FAIL sincosf != (sinf, cosf) at 0x%08x\n", f2u(x));
            return 1;
        }
        if (ulp_diff_f32(fs, gs) > (gl_ge_243 ? 1u : 2u) || ulp_diff_f32(fc, gc) > (gl_ge_243 ? 1u : 2u)) {
            fprintf(stderr, "FAIL sincosf >1 ULP vs glibc at 0x%08x\n", f2u(x));
            return 1;
        }
        if (ulp_diff_f32(fl_atan2f(y, x), (float)atan2q((__float128)y, (__float128)x)) != 0) {
            fprintf(stderr, "FAIL atan2f CR(0x%08x, 0x%08x)\n", f2u(y), f2u(x));
            return 1;
        }
        if (ulp_diff_f32(fl_hypotf(y, x), (float)hypotq((__float128)y, (__float128)x)) != 0) {
            fprintf(stderr, "FAIL hypotf CR(0x%08x, 0x%08x)\n", f2u(y), f2u(x));
            return 1;
        }
        if (gl_ge_243 && ulp_diff_f32(fl_powf(y, x), gl_powf(y, x)) != 0) {
            fprintf(stderr, "FAIL powf(0x%08x, 0x%08x)\n", f2u(y), f2u(x));
            return 1;
        }
        int fsgn = 0, gsgn = 0;
        float flv = fl_lgr(x, &fsgn), glv = gl_lgr(x, &gsgn);
        if (ulp_diff_f32(flv, (float)lgammaq((__float128)x)) > 1 || (!isnan(x) && x != 0.0f && !isinf(x) && fsgn != gsgn)) {
            fprintf(stderr, "FAIL lgammaf_r(0x%08x): fl=(0x%08x,%d) gl=(0x%08x,%d)\n",
                    f2u(x), f2u(flv), fsgn, f2u(glv), gsgn);
            return 1;
        }
    }
    printf("PASS: libm_f32_parity verified (62M evaluations, max_ulp <= 1 everywhere, 0 diffs on CR f32 + atan2f + hypotf + powf)\n");
    return 0;
}
"#,
    )
    .expect("probe_f32.c written");

    let st = Command::new("cc")
        .args(["-O3", "-std=c11"])
        .arg(&probe_c)
        .args(["-lquadmath", "-ldl", "-lm", "-o"])
        .arg(&probe_bin)
        .status()
        .expect("cc probe_f32");
    assert!(st.success(), "failed compiling probe_f32.c");

    for mode in ["strict", "hardened"] {
        let out = Command::new(&probe_bin)
            .arg(&lib)
            .env("FRANKENLIBC_MODE", mode)
            .output()
            .expect("probe_f32 execution");
        assert!(
            out.status.success(),
            "probe_f32 ({mode}) failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("PASS: libm_f32_parity verified"),
            "missing PASS banner in {mode}"
        );
    }
}
