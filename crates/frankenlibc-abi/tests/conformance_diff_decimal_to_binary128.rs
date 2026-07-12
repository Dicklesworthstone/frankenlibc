//! Differential gate: the correctly-rounded decimal->binary128 core
//! (decimal_to_binary128, the heart of strtof128 / bd-nkr0ga) matches glibc's
//! strtof128 bit-for-bit.
//!
//! glibc's strtof128 returns _Float128 correctly (only fl's wrapper is the
//! broken one being fixed); declaring it with an `f128` return links the real
//! glibc symbol. For each (sign, digits, dexp) we feed glibc the canonical
//! string "{sign}{digits}e{dexp}" and compare to our core's bits.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_core::float128::decimal_to_binary128;
use std::ffi::{CString, c_char};

unsafe extern "C" {
    fn strtof128(nptr: *const c_char, endptr: *mut *mut c_char) -> f128;
}

fn glibc_bits(s: &str) -> u128 {
    let c = CString::new(s).unwrap();
    let v = unsafe { strtof128(c.as_ptr(), std::ptr::null_mut()) };
    v.to_bits()
}

fn check(neg: bool, digits: &str, dexp: i32, mism: &mut Vec<String>) {
    let s = format!("{}{}e{}", if neg { "-" } else { "" }, digits, dexp);
    let g = glibc_bits(&s);
    let f = decimal_to_binary128(neg, digits.as_bytes(), dexp);
    if g != f {
        mism.push(format!("{s:?}: glibc={g:#034x} fl={f:#034x}"));
    }
}

#[test]
fn decimal_to_binary128_matches_glibc() {
    let mut mism = Vec::new();

    // Curated cases incl. rounding boundaries and magnitude extremes.
    let curated: &[(&str, i32)] = &[
        ("1", 0),
        ("1", -1),
        ("3", -1),
        ("123456789", -4),
        ("1", 100),
        ("1", -100),
        ("99999999999999999999999999999999999", 0),
        ("5", -324),
        ("2", 4900),
        ("2", -4900),
        ("1", 4932),
        ("1", 4933), // overflow -> inf
        ("1", -4940),
        ("1", -4970), // deep subnormal
        ("1", -5000), // underflow -> 0
        ("4824", -4),
        ("100000000000000000000000000000000005", -1),
        ("314159265358979323846264338327950288", -35),
    ];
    for &(d, e) in curated {
        check(false, d, e, &mut mism);
        check(true, d, e, &mut mism);
    }

    // Deterministic random: digit strings of varied length over a wide exponent
    // range (covers normal, subnormal, overflow, and many rounding boundaries).
    let mut state: u64 = 0xdead_beef_1234_5678;
    let mut rng = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state
    };
    for _ in 0..1200 {
        let len = 1 + (rng() % 38) as usize;
        let mut d = String::with_capacity(len);
        d.push((b'1' + (rng() % 9) as u8) as char); // nonzero lead
        for _ in 1..len {
            d.push((b'0' + (rng() % 10) as u8) as char);
        }
        let dexp = (rng() % 9940) as i32 - 4970; // [-4970, 4969]
        let neg = rng() & 1 == 0;
        check(neg, &d, dexp, &mut mism);
        if mism.len() > 40 {
            break;
        }
    }

    assert!(
        mism.is_empty(),
        "decimal_to_binary128 diverged ({}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}
