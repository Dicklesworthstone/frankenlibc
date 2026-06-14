#![cfg(target_os = "linux")]

//! Differential conformance gate for `imaxdiv` (<inttypes.h>).
//!
//! `imaxdiv` returns an `imaxdiv_t { intmax_t quot; intmax_t rem; }` BY VALUE.
//! On x86-64 SysV that 16-byte two-integer struct is returned in RAX:RDX (it is
//! INTEGER-class, not memory-class — no hidden sret pointer). fl previously
//! declared `imaxdiv(numer, denom, *mut i64)`, an sret form that does not match
//! how any C compiler emits the call: it read a garbage register as the result
//! pointer and corrupted memory. This test pins the by-value ABI against host
//! glibc, including the C truncation-toward-zero sign rules for the remainder.

use frankenlibc_abi::stdlib_abi::{self as fl, CImaxdiv};

#[repr(C)]
struct HostImaxdiv {
    quot: i64,
    rem: i64,
}

unsafe extern "C" {
    fn imaxdiv(numer: i64, denom: i64) -> HostImaxdiv;
}

#[test]
fn imaxdiv_matches_glibc() {
    // Cover both signs of numerator and denominator (C truncates toward zero,
    // so rem takes the sign of the numerator), exact divisions, and edges.
    let cases: &[(i64, i64)] = &[
        (7, 2),
        (-7, 2),
        (7, -2),
        (-7, -2),
        (8, 4),
        (-8, 4),
        (0, 5),
        (5, 1),
        (-5, 1),
        (1, 1),
        (100, 7),
        (-100, 7),
        (100, -7),
        (-100, -7),
        (i64::MAX, 3),
        (i64::MIN, 3),
        (i64::MAX, -1),
        (i64::MAX, i64::MAX),
        (i64::MIN, i64::MAX),
        (123456789012345, 1000),
        (-123456789012345, 1000),
        (42, 13),
        (-42, 13),
        (1, i64::MAX),
    ];

    let mut div: Vec<String> = Vec::new();
    for &(n, d) in cases {
        // i64::MIN / -1 overflows in two's complement; both glibc and Rust would
        // trap, so skip that single UB pair rather than invoke it.
        if n == i64::MIN && d == -1 {
            continue;
        }
        let CImaxdiv {
            quot: fq,
            rem: fr,
        } = fl::imaxdiv(n, d);
        let h = unsafe { imaxdiv(n, d) };
        if fq != h.quot || fr != h.rem {
            div.push(format!(
                "imaxdiv({n}, {d}) = {{quot:{fq}, rem:{fr}}}, glibc = {{quot:{}, rem:{}}}",
                h.quot, h.rem
            ));
        }
    }
    assert!(
        div.is_empty(),
        "imaxdiv divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
