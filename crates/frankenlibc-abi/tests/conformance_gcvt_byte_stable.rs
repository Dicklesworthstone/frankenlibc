#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Byte-stability gate for gcvt after moving the float render off the heap
//! (format! -> stack StackStr in format_fixed/format_scientific). Pins the exact
//! output over specials + 100k random doubles x all ndigit; must stay identical.
use frankenlibc_abi::stdlib_abi as fs;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::os::raw::c_char;
#[test]
#[allow(clippy::approx_constant)]
fn gcvt_golden_byte_stable() {
    let mut h = Sha256::new();
    let mut buf = [0u8; 512];
    let mut seed: u64 = 0x1234abcd;
    let mut rng = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let specials = [
        0.0f64,
        -0.0,
        1.0,
        -1.0,
        f64::NAN,
        -f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        9.9999e-5,
        999999.9,
        1e-4,
        1e6,
        3.14159265358979,
        2.5,
        0.1,
        123456.789,
        1e300,
        1e-300,
        9.999999999999e-5,
        0.0001,
        100000.0,
        1000000.0,
    ];
    let mut n = 0u64;
    for &v in &specials {
        for nd in -2i32..20 {
            let p = unsafe { fs::gcvt(v, nd, buf.as_mut_ptr() as *mut c_char) };
            let s = if p.is_null() {
                b"<null>".to_vec()
            } else {
                unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
            };
            h.update(&s);
            h.update([0]);
            n += 1;
        }
    }
    for _ in 0..100000 {
        let bits = rng();
        let v = f64::from_bits(bits);
        if !v.is_finite() {
            continue;
        }
        let nd = ((rng() % 24) as i32) - 2;
        let p = unsafe { fs::gcvt(v, nd, buf.as_mut_ptr() as *mut c_char) };
        let s = if p.is_null() {
            b"<null>".to_vec()
        } else {
            unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
        };
        h.update(&s);
        h.update([0]);
        n += 1;
    }
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("GCVT GOLDEN n={n} sha256={hex}");
    assert_eq!(n, 100432);
    assert_eq!(
        hex, "9f2591668d6b41f486cfae62fd71ec7cf6666c60e547a8358f83761a05040819",
        "gcvt output changed"
    );
}
