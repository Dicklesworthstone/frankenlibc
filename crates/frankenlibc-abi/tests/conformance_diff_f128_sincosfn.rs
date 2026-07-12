//! Differential gate: f128 sincosf128 matches glibc bit-for-bit (bd-9z5ikz).
//! Was a garbage f64-ABI stub. The fix is glibc's s_sincosl over the byte-exact
//! rem_pio2l + kernel_sincosl, so both outputs are byte-exact.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;

unsafe extern "C" {
    fn sincosf128(x: f128, s: *mut f128, c: *mut f128);
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        0.5,
        1.0,
        2.0,
        3.0,
        10.0,
        100.0,
        1e6f128,
        1e30f128,
        1e300f128,
        1e4000f128,
        0.1484375f128,
        1e-20f128,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112),
        f128::from_bits(0xffff_u128 << 112),
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)),
    ];
    let mut q: i64 = -8000;
    while q <= 8000 {
        v.push(q as f128 / 500.0);
        q += 1;
    }
    let mut st: u64 = 0x53_43_66_6e_31_32_38_ff;
    for _ in 0..4000 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (hi % 0x7fff) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_sincos_fn_matches_glibc() {
    let mut mism = Vec::new();
    for &x in &values() {
        let (mut gs, mut gc) = (0.0f128, 0.0f128);
        let (mut fs, mut fc) = (0.0f128, 0.0f128);
        unsafe {
            sincosf128(x, &mut gs, &mut gc);
            ma::sincosf128(x, &mut fs, &mut fc);
        }
        if gs.to_bits() != fs.to_bits() || gc.to_bits() != fc.to_bits() {
            mism.push(format!(
                "sincos({:#034x}): glibc=({:#034x},{:#034x}) fl=({:#034x},{:#034x})",
                x.to_bits(),
                gs.to_bits(),
                gc.to_bits(),
                fs.to_bits(),
                fc.to_bits()
            ));
        }
    }
    assert!(
        mism.is_empty(),
        "sincosf128 diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
