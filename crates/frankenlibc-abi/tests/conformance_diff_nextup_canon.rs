//! Conformance gate for C23 nextup/nextdown/canonicalize (+f32) vs host glibc.
//! glibc may expose these as IFUNCs (a raw fn pointer hits the resolver), so the
//! expected (bits/ret) tuples are GROUND TRUTH captured from a gcc -fno-builtin
//! program that calls them directly. fl is exercised via Rust paths. Covers
//! ±0, ±inf, the subnormal/zero boundary, MAX, quiet NaN, and SIGNALING NaN
//! (which nextup/nextdown/canonicalize all quiet — set the mantissa MSB).
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]
use frankenlibc_abi::math_abi as fl;

// (x_bits, nextup_bits, nextdown_bits)
const NU64: &[(u64, u64, u64)] = &[
    (0x0000000000000000, 0x0000000000000001, 0x8000000000000001),
    (0x8000000000000000, 0x0000000000000001, 0x8000000000000001),
    (0x3ff0000000000000, 0x3ff0000000000001, 0x3fefffffffffffff),
    (0xbff0000000000000, 0xbfefffffffffffff, 0xbff0000000000001),
    (0x7ff0000000000000, 0x7ff0000000000000, 0x7fefffffffffffff),
    (0xfff0000000000000, 0xffefffffffffffff, 0xfff0000000000000),
    (0x7ff8000000000000, 0x7ff8000000000000, 0x7ff8000000000000),
    (0xfff8000000000000, 0xfff8000000000000, 0xfff8000000000000),
    (0x0000000000000001, 0x0000000000000002, 0x0000000000000000),
    (0x8000000000000001, 0x8000000000000000, 0x8000000000000002),
    (0x0010000000000000, 0x0010000000000001, 0x000fffffffffffff),
    (0x7fefffffffffffff, 0x7ff0000000000000, 0x7feffffffffffffe),
    (0xffefffffffffffff, 0xffeffffffffffffe, 0xfff0000000000000),
    (0x3fe0000000000000, 0x3fe0000000000001, 0x3fdfffffffffffff),
    (0x7ff4000000000000, 0x7ffc000000000000, 0x7ffc000000000000),
    (0x7ffc000000000000, 0x7ffc000000000000, 0x7ffc000000000000),
];
const NU32: &[(u32, u32, u32)] = &[
    (0x00000000, 0x00000001, 0x80000001),
    (0x80000000, 0x00000001, 0x80000001),
    (0x3f800000, 0x3f800001, 0x3f7fffff),
    (0xbf800000, 0xbf7fffff, 0xbf800001),
    (0x7f800000, 0x7f800000, 0x7f7fffff),
    (0xff800000, 0xff7fffff, 0xff800000),
    (0x7fc00000, 0x7fc00000, 0x7fc00000),
    (0x00000001, 0x00000002, 0x00000000),
    (0x80000001, 0x80000000, 0x80000002),
    (0x7f7fffff, 0x7f800000, 0x7f7ffffe),
    (0x7fa00000, 0x7fe00000, 0x7fe00000),
];
// (x_bits, ret, out_bits)
const CN64: &[(u64, i32, u64)] = &[
    (0x0000000000000000, 0, 0x0000000000000000),
    (0x8000000000000000, 0, 0x8000000000000000),
    (0x3ff0000000000000, 0, 0x3ff0000000000000),
    (0xbff0000000000000, 0, 0xbff0000000000000),
    (0x7ff0000000000000, 0, 0x7ff0000000000000),
    (0xfff0000000000000, 0, 0xfff0000000000000),
    (0x7ff8000000000000, 0, 0x7ff8000000000000),
    (0xfff8000000000000, 0, 0xfff8000000000000),
    (0x0000000000000001, 0, 0x0000000000000001),
    (0x8000000000000001, 0, 0x8000000000000001),
    (0x0010000000000000, 0, 0x0010000000000000),
    (0x7fefffffffffffff, 0, 0x7fefffffffffffff),
    (0xffefffffffffffff, 0, 0xffefffffffffffff),
    (0x3fe0000000000000, 0, 0x3fe0000000000000),
    (0x7ff4000000000000, 0, 0x7ffc000000000000),
    (0x7ffc000000000000, 0, 0x7ffc000000000000),
];
const CN32: &[(u32, i32, u32)] = &[
    (0x00000000, 0, 0x00000000),
    (0x80000000, 0, 0x80000000),
    (0x3f800000, 0, 0x3f800000),
    (0xbf800000, 0, 0xbf800000),
    (0x7f800000, 0, 0x7f800000),
    (0xff800000, 0, 0xff800000),
    (0x7fc00000, 0, 0x7fc00000),
    (0x00000001, 0, 0x00000001),
    (0x80000001, 0, 0x80000001),
    (0x7f7fffff, 0, 0x7f7fffff),
    (0x7fa00000, 0, 0x7fe00000),
];
const CN128: &[(u128, i32, u128)] = &[
    (
        0x00000000000000000000000000000000,
        0,
        0x00000000000000000000000000000000,
    ),
    (
        0x80000000000000000000000000000000,
        0,
        0x80000000000000000000000000000000,
    ),
    (
        0x3fff0000000000000000000000000000,
        0,
        0x3fff0000000000000000000000000000,
    ),
    (
        0xbfff0000000000000000000000000000,
        0,
        0xbfff0000000000000000000000000000,
    ),
    (
        0x7fff0000000000000000000000000000,
        0,
        0x7fff0000000000000000000000000000,
    ),
    (
        0xffff0000000000000000000000000000,
        0,
        0xffff0000000000000000000000000000,
    ),
    (
        0x7fff8000000000000000000000000000,
        0,
        0x7fff8000000000000000000000000000,
    ),
    (
        0xffff8000000000000000000000000000,
        0,
        0xffff8000000000000000000000000000,
    ),
    (
        0x00000000000000000000000000000001,
        0,
        0x00000000000000000000000000000001,
    ),
    (
        0x80000000000000000000000000000001,
        0,
        0x80000000000000000000000000000001,
    ),
    (
        0x00010000000000000000000000000000,
        0,
        0x00010000000000000000000000000000,
    ),
    (
        0x7ffeffffffffffffffffffffffffffff,
        0,
        0x7ffeffffffffffffffffffffffffffff,
    ),
    (
        0xfffeffffffffffffffffffffffffff,
        0,
        0xfffeffffffffffffffffffffffffff,
    ),
    (
        0x3ffe0000000000000000000000000000,
        0,
        0x3ffe0000000000000000000000000000,
    ),
    (
        0x7fff4000000000000000000000000000,
        0,
        0x7fffc000000000000000000000000000,
    ),
    (
        0xffff4000000000000000000000000000,
        0,
        0xffffc000000000000000000000000000,
    ),
];

#[test]
fn nextup_canonicalize_matches_glibc() {
    let mut div: Vec<String> = Vec::new();
    for &(xb, up, dn) in NU64 {
        let x = f64::from_bits(xb);
        let fu = unsafe { fl::nextup(x) }.to_bits();
        let fd = unsafe { fl::nextdown(x) }.to_bits();
        if fu != up {
            div.push(format!(
                "nextup(0x{:016x}): fl=0x{:016x} glibc=0x{:016x}",
                xb, fu, up
            ));
        }
        if fd != dn {
            div.push(format!(
                "nextdown(0x{:016x}): fl=0x{:016x} glibc=0x{:016x}",
                xb, fd, dn
            ));
        }
    }
    for &(xb, up, dn) in NU32 {
        let x = f32::from_bits(xb);
        let fu = unsafe { fl::nextupf(x) }.to_bits();
        let fd = unsafe { fl::nextdownf(x) }.to_bits();
        if fu != up {
            div.push(format!(
                "nextupf(0x{:08x}): fl=0x{:08x} glibc=0x{:08x}",
                xb, fu, up
            ));
        }
        if fd != dn {
            div.push(format!(
                "nextdownf(0x{:08x}): fl=0x{:08x} glibc=0x{:08x}",
                xb, fd, dn
            ));
        }
    }
    for &(xb, ret, out) in CN64 {
        let x = f64::from_bits(xb);
        let mut o = 99.0f64;
        let r = unsafe { fl::canonicalize(&mut o, &x) };
        let ob = o.to_bits();
        if r != ret || ob != out {
            div.push(format!(
                "canonicalize(0x{:016x}): fl=ret{}/0x{:016x} glibc=ret{}/0x{:016x}",
                xb, r, ob, ret, out
            ));
        }
    }
    for &(xb, ret, out) in CN32 {
        let x = f32::from_bits(xb);
        let mut o = 99.0f32;
        let r = unsafe { fl::canonicalizef(&mut o, &x) };
        let ob = o.to_bits();
        if r != ret || ob != out {
            div.push(format!(
                "canonicalizef(0x{:08x}): fl=ret{}/0x{:08x} glibc=ret{}/0x{:08x}",
                xb, r, ob, ret, out
            ));
        }
    }
    for &(xb, ret, out) in CN128 {
        let x = f128::from_bits(xb);
        let mut o = 99.0f128;
        let r = unsafe { fl::canonicalizef128(&mut o, &x) };
        let ob = o.to_bits();
        if r != ret || ob != out {
            div.push(format!(
                "canonicalizef128(0x{:032x}): fl=ret{}/0x{:032x} glibc=ret{}/0x{:032x}",
                xb, r, ob, ret, out
            ));
        }
    }
    assert!(
        div.is_empty(),
        "nextup/canonicalize divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
