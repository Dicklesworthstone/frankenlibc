//! Differential gate: the C23 narrowing operations from binary128 operands
//! (fN{add,sub,mul,div,sqrt,fma}f128 for N in {f32, f32x=f64, f64}) match glibc
//! bit-for-bit (bd-9z5ikz). All were garbage f64-ABI stubs; the fix computes
//! each op once in f128 then round-to-odd so the f64/f32 cast is the single
//! correctly-rounded narrow result (defeating the double rounding). The f64x*
//! variants return 80-bit long double (unrepresentable in safe Rust) and are
//! out of scope.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;

unsafe extern "C" {
    fn f32addf128(x: f128, y: f128) -> f32;
    fn f32xaddf128(x: f128, y: f128) -> f64;
    fn f64addf128(x: f128, y: f128) -> f64;
    fn f32subf128(x: f128, y: f128) -> f32;
    fn f32xsubf128(x: f128, y: f128) -> f64;
    fn f64subf128(x: f128, y: f128) -> f64;
    fn f32mulf128(x: f128, y: f128) -> f32;
    fn f32xmulf128(x: f128, y: f128) -> f64;
    fn f64mulf128(x: f128, y: f128) -> f64;
    fn f32divf128(x: f128, y: f128) -> f32;
    fn f32xdivf128(x: f128, y: f128) -> f64;
    fn f64divf128(x: f128, y: f128) -> f64;
    fn f32sqrtf128(x: f128) -> f32;
    fn f32xsqrtf128(x: f128) -> f64;
    fn f64sqrtf128(x: f128) -> f64;
    fn f32fmaf128(x: f128, y: f128, z: f128) -> f32;
    fn f32xfmaf128(x: f128, y: f128, z: f128) -> f64;
    fn f64fmaf128(x: f128, y: f128, z: f128) -> f64;
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        2.0,
        0.5,
        3.0,
        -3.0,
        1e30f128,
        1e-30f128,
        1e300f128,
        1e-300f128,
        1e4000f128,
        1e-4000f128,
        f128::MIN_POSITIVE,
        f128::MAX,
        f128::from_bits(1),                                     // smallest subnormal
        f128::from_bits(0x7fff_u128 << 112),                    // +inf
        f128::from_bits(0xffff_u128 << 112),                    // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
        // Half-ULP-ish at f64/f32 boundaries: 1 + 2^-53, 1 + 2^-24, plus tiny.
        f128::from_bits((16383u128 << 112) | (1u128 << (112 - 53))),
        f128::from_bits((16383u128 << 112) | (1u128 << (112 - 24))),
    ];
    let mut st: u64 = 0xa5a5_1234_dead_c0de;
    for _ in 0..200 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = st;
        // Bias exponent toward the f64/f32-representable range so casts mostly
        // produce finite results that exercise rounding, plus some extremes.
        let ef = (0x3c00 + (hi % 0x0900)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 17) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_narrow_matches_glibc() {
    let vals = values();
    let mut mism = Vec::new();
    // Binary ops: (name, glibc-f32?, glibc fn, fl fn) — handle f32 vs f64 result.
    macro_rules! bin64 {
        ($name:literal, $g:ident, $f:path) => {
            for &x in &vals {
                for &y in &vals {
                    let g = unsafe { $g(x, y) }.to_bits();
                    let f = unsafe { $f(x, y) }.to_bits();
                    if g != f {
                        mism.push(format!("{} x={:#034x} y={:#034x}: g={g:#018x} f={f:#018x}", $name, x.to_bits(), y.to_bits()));
                    }
                }
            }
        };
    }
    macro_rules! bin32 {
        ($name:literal, $g:ident, $f:path) => {
            for &x in &vals {
                for &y in &vals {
                    let g = unsafe { $g(x, y) }.to_bits();
                    let f = unsafe { $f(x, y) }.to_bits();
                    if g != f {
                        mism.push(format!("{} x={:#034x} y={:#034x}: g={g:#010x} f={f:#010x}", $name, x.to_bits(), y.to_bits()));
                    }
                }
            }
        };
    }
    bin32!("f32add", f32addf128, ma::f32addf128);
    bin64!("f32xadd", f32xaddf128, ma::f32xaddf128);
    bin64!("f64add", f64addf128, ma::f64addf128);
    bin32!("f32sub", f32subf128, ma::f32subf128);
    bin64!("f32xsub", f32xsubf128, ma::f32xsubf128);
    bin64!("f64sub", f64subf128, ma::f64subf128);
    bin32!("f32mul", f32mulf128, ma::f32mulf128);
    bin64!("f32xmul", f32xmulf128, ma::f32xmulf128);
    bin64!("f64mul", f64mulf128, ma::f64mulf128);
    bin32!("f32div", f32divf128, ma::f32divf128);
    bin64!("f32xdiv", f32xdivf128, ma::f32xdivf128);
    bin64!("f64div", f64divf128, ma::f64divf128);

    // sqrt (unary)
    for &x in &vals {
        let g = unsafe { f32sqrtf128(x) }.to_bits();
        let f = unsafe { ma::f32sqrtf128(x) }.to_bits();
        if g != f {
            mism.push(format!("f32sqrt x={:#034x}: g={g:#010x} f={f:#010x}", x.to_bits()));
        }
        for (gv, fv) in [
            (unsafe { f32xsqrtf128(x) }.to_bits(), unsafe { ma::f32xsqrtf128(x) }.to_bits()),
            (unsafe { f64sqrtf128(x) }.to_bits(), unsafe { ma::f64sqrtf128(x) }.to_bits()),
        ] {
            if gv != fv {
                mism.push(format!("sqrt64 x={:#034x}: g={gv:#018x} f={fv:#018x}", x.to_bits()));
            }
        }
    }

    // fma (ternary) — a bounded triple sweep over a representative subset.
    let sub: Vec<f128> = vals.iter().copied().take(28).collect();
    for &x in &sub {
        for &y in &sub {
            for &z in &sub {
                let g = unsafe { f32fmaf128(x, y, z) }.to_bits();
                let f = unsafe { ma::f32fmaf128(x, y, z) }.to_bits();
                if g != f {
                    mism.push(format!("f32fma x={:#034x} y={:#034x} z={:#034x}: g={g:#010x} f={f:#010x}", x.to_bits(), y.to_bits(), z.to_bits()));
                }
                let g2 = unsafe { f64fmaf128(x, y, z) }.to_bits();
                let f2 = unsafe { ma::f64fmaf128(x, y, z) }.to_bits();
                if g2 != f2 {
                    mism.push(format!("f64fma x={:#034x} y={:#034x} z={:#034x}: g={g2:#018x} f={f2:#018x}", x.to_bits(), y.to_bits(), z.to_bits()));
                }
                let g3 = unsafe { f32xfmaf128(x, y, z) }.to_bits();
                let f3 = unsafe { ma::f32xfmaf128(x, y, z) }.to_bits();
                if g3 != f3 {
                    mism.push(format!("f32xfma x={:#034x} y={:#034x} z={:#034x}: g={g3:#018x} f={f3:#018x}", x.to_bits(), y.to_bits(), z.to_bits()));
                }
            }
        }
    }

    assert!(
        mism.is_empty(),
        "f128 narrowing diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(40).cloned().collect::<Vec<_>>().join("\n")
    );
}
