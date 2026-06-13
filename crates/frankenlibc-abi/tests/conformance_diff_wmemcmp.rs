//! Differential gate for the public `wmemcmp` ABI after routing its bounded
//! wide compare through the SIMD core `wmemcmp` (unrolled Simd<u32,N> panels)
//! instead of a scalar element loop. fl must sign-match host glibc `wmemcmp`
//! for every n, first-difference position (incl. straddling the SIMD panel/
//! unroll boundary), and sign of the differing wchar_t (signed i32 on Linux,
//! so values across the sign boundary matter).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::wchar_abi::wmemcmp as fl_wmemcmp;
use std::os::raw::c_int;

unsafe extern "C" {
    fn wmemcmp(s1: *const u32, s2: *const u32, n: usize) -> c_int;
}

fn sign(x: i32) -> i32 {
    x.signum()
}

#[test]
fn wmemcmp_matches_glibc() {
    let mut checked = 0u64;
    // Values spanning the signed wchar_t boundary (0x8000_0000 is negative as i32).
    let vals: [u32; 6] = [0, 1, 0x7FFF_FFFF, 0x8000_0000, 0x8000_0001, 0xFFFF_FFFF];

    for len in 0usize..70 {
        // Base buffer of a repeating pattern.
        let base: Vec<u32> = (0..len).map(|k| (k as u32).wrapping_mul(2654435761)).collect();

        // Equal case.
        let a = base.clone();
        let b = base.clone();
        let fl = unsafe { fl_wmemcmp(a.as_ptr(), b.as_ptr(), len) };
        let gl = unsafe { wmemcmp(a.as_ptr(), b.as_ptr(), len) };
        assert_eq!(sign(fl), sign(gl), "wmemcmp equal len={len}");
        checked += 1;

        // Single-element difference at every position, with every replacement value.
        for pos in 0..len {
            for &nv in &vals {
                if base[pos] == nv {
                    continue;
                }
                let mut b2 = base.clone();
                b2[pos] = nv;
                // Compare over n = len AND a few n straddling pos.
                for &n in &[len, pos, pos + 1, (pos + 8).min(len)] {
                    let fln = unsafe { fl_wmemcmp(a.as_ptr(), b2.as_ptr(), n) };
                    let gln = unsafe { wmemcmp(a.as_ptr(), b2.as_ptr(), n) };
                    assert_eq!(
                        sign(fln),
                        sign(gln),
                        "wmemcmp len={len} pos={pos} nv={nv:#x} n={n}: fl={fln} gl={gln}"
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 10_000, "corpus unexpectedly small: {checked}");
}
