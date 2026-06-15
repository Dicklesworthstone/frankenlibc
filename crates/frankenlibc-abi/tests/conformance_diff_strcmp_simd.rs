#![cfg(target_os = "linux")]
//! Isomorphism + golden gate for the 32-byte portable-SIMD fast path added to
//! the shared ABI `scan_strcmp` (used by strcmp and strncmp). Widened from an
//! 8-byte SWAR word compare to AVX width to close the vs-glibc throughput gap.
//! 200000 random pairs (mismatches at random positions, mixed lengths straddling
//! the 32-byte panel, high/low bytes, random strncmp n) agree exactly with host
//! glibc strcmp/strncmp; a golden sha256 of the sign-result stream pins it.
#![allow(unsafe_code)]
use frankenlibc_abi::string_abi as fa;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::os::raw::c_char;
unsafe extern "C" {
    fn strcmp(a: *const c_char, b: *const c_char) -> i32;
    fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> i32;
}
fn norm(x: i32) -> i32 {
    x.signum()
}
#[test]
fn iso() {
    let alpha = *b"abcAZz0~\x01\xffm ";
    let mut seed: u64 = 0xABCDEF;
    let mut rng = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut h = Sha256::new();
    let mut div = 0u32;
    let mut n = 0u64;
    for _ in 0..200000 {
        let len = (rng() as usize) % 70;
        let a: Vec<u8> = (0..len)
            .map(|_| alpha[(rng() as usize) % alpha.len()])
            .collect();
        let mut b = a.clone();
        if rng() & 1 == 0 {
            let bl = b.len();
            if bl > 0 {
                let k = (rng() as usize) % bl;
                b[k] = alpha[(rng() as usize) % alpha.len()];
            }
        }
        let ca = CString::new(a.clone()).unwrap();
        let cb = CString::new(b.clone()).unwrap();
        let fc = norm(unsafe { fa::strcmp(ca.as_ptr(), cb.as_ptr()) });
        let gc = norm(unsafe { strcmp(ca.as_ptr(), cb.as_ptr()) });
        if fc != gc {
            div += 1;
            if div <= 5 {
                eprintln!("DIV strcmp a={:?} b={:?} fl={fc} gl={gc}", ca, cb);
            }
        }
        let nn = (rng() as usize) % 75;
        let fnc = norm(unsafe { fa::strncmp(ca.as_ptr(), cb.as_ptr(), nn) });
        let gnc = norm(unsafe { strncmp(ca.as_ptr(), cb.as_ptr(), nn) });
        if fnc != gnc {
            div += 1;
            if div <= 5 {
                eprintln!("DIV strncmp n={nn} a={:?} b={:?} fl={fnc} gl={gnc}", ca, cb);
            }
        }
        h.update([fc as u8, fnc as u8]);
        n += 1;
    }
    let dig = h.finalize();
    let hex: String = dig.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("golden={hex} n={n} div={div}");
    assert_eq!(n, 200000);
    assert_eq!(
        hex, "f10c9c405f5a72d844f7c577ff68590ad1a143efa165bbb05d6bc3fe4c520c53",
        "strcmp/strncmp sign-result golden changed"
    );
    assert_eq!(div, 0);
}
