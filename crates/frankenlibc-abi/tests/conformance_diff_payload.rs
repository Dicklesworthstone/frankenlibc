//! Conformance gate for C23 NaN-payload fns getpayload/setpayload/setpayloadsig
//! (+f32) vs host glibc. setpayload* require a non-negative INTEGER payload in
//! range and set *res to +0 on failure; getpayload extracts the mantissa
//! payload (or -1 for a non-NaN). Golden tuples captured from a gcc
//! -fno-builtin oracle (these may be IFUNCs). fl exercised via Rust paths.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use frankenlibc_abi::math_abi as fl;
// setpayload/setpayloadsig f64: (payload_bits, ret, out_bits)
const SP64: &[(u64, i32, u64)] = &[
    (0x0000000000000000, 0, 0x7ff8000000000000),
    (0x3ff0000000000000, 0, 0x7ff8000000000001),
    (0x4014000000000000, 0, 0x7ff8000000000005),
    (0x3ff8000000000000, 1, 0x0000000000000000),
    (0xbff0000000000000, 1, 0x0000000000000000),
    (0x431ffffffffffffc, 0, 0x7fffffffffffffff),
    (0x4320000000000000, 1, 0x0000000000000000),
    (0x4008000000000000, 0, 0x7ff8000000000003),
    (0x7ff8000000000000, 1, 0x0000000000000000),
    (0x7ff0000000000000, 1, 0x0000000000000000),
    (0x404559999999999a, 1, 0x0000000000000000),
    (0x3fe0000000000000, 1, 0x0000000000000000),
];
const SS64: &[(u64, i32, u64)] = &[
    (0x0000000000000000, 1, 0x0000000000000000),
    (0x3ff0000000000000, 0, 0x7ff0000000000001),
    (0x4014000000000000, 0, 0x7ff0000000000005),
    (0x3ff8000000000000, 1, 0x0000000000000000),
    (0xbff0000000000000, 1, 0x0000000000000000),
    (0x431ffffffffffffc, 0, 0x7ff7ffffffffffff),
    (0x4320000000000000, 1, 0x0000000000000000),
    (0x4008000000000000, 0, 0x7ff0000000000003),
    (0x7ff8000000000000, 1, 0x0000000000000000),
    (0x7ff0000000000000, 1, 0x0000000000000000),
    (0x404559999999999a, 1, 0x0000000000000000),
    (0x3fe0000000000000, 1, 0x0000000000000000),
];
const SP32: &[(u32, i32, u32)] = &[
    (0x00000000, 0, 0x7fc00000),
    (0x3f800000, 0, 0x7fc00001),
    (0x40a00000, 0, 0x7fc00005),
    (0x3fc00000, 1, 0x00000000),
    (0xbf800000, 1, 0x00000000),
    (0x4a7ffffc, 0, 0x7fffffff),
    (0x4a800000, 1, 0x00000000),
    (0x40400000, 0, 0x7fc00003),
    (0x7fc00000, 1, 0x00000000),
    (0x7f800000, 1, 0x00000000),
    (0x422acccd, 1, 0x00000000),
    (0x3f000000, 1, 0x00000000),
];
const SS32: &[(u32, i32, u32)] = &[
    (0x00000000, 1, 0x00000000),
    (0x3f800000, 0, 0x7f800001),
    (0x40a00000, 0, 0x7f800005),
    (0x3fc00000, 1, 0x00000000),
    (0xbf800000, 1, 0x00000000),
    (0x4a7ffffc, 0, 0x7fbfffff),
    (0x4a800000, 1, 0x00000000),
    (0x40400000, 0, 0x7f800003),
    (0x7fc00000, 1, 0x00000000),
    (0x7f800000, 1, 0x00000000),
    (0x422acccd, 1, 0x00000000),
    (0x3f000000, 1, 0x00000000),
];
const GP64: &[(u64, u64)] = &[
    (0x7ff8000000000000, 0x0000000000000000),
    (0x7ff8000000000005, 0x4014000000000000),
    (0x7ff0000000000005, 0x4014000000000000),
    (0xfff8000000000005, 0x4014000000000000),
    (0x3ff0000000000000, 0xbff0000000000000),
    (0x7ff0000000000000, 0xbff0000000000000),
    (0x0000000000000000, 0xbff0000000000000),
    (0x7fffffffffffffff, 0x431ffffffffffffc),
];
const GP32: &[(u32, u32)] = &[
    (0x7fc00000, 0x00000000),
    (0x7fc00005, 0x40a00000),
    (0x7f800005, 0x40a00000),
    (0xffc00005, 0x40a00000),
    (0x3f800000, 0xbf800000),
    (0x7f800000, 0xbf800000),
    (0x00000000, 0xbf800000),
    (0x7fffffff, 0x4a7ffffc),
];

#[test]
fn payload_matches_glibc() {
    let mut div: Vec<String> = Vec::new();
    for &(pb, ret, out) in SP64 {
        let mut o = f64::from_bits(0x1234567890abcdef);
        let r = unsafe { fl::setpayload(&mut o, f64::from_bits(pb)) };
        if r != ret || o.to_bits() != out {
            div.push(format!(
                "setpayload(0x{:016x}): fl=ret{}/0x{:016x} glibc=ret{}/0x{:016x}",
                pb,
                r,
                o.to_bits(),
                ret,
                out
            ));
        }
    }
    for &(pb, ret, out) in SS64 {
        let mut o = f64::from_bits(0x1234567890abcdef);
        let r = unsafe { fl::setpayloadsig(&mut o, f64::from_bits(pb)) };
        if r != ret || o.to_bits() != out {
            div.push(format!(
                "setpayloadsig(0x{:016x}): fl=ret{}/0x{:016x} glibc=ret{}/0x{:016x}",
                pb,
                r,
                o.to_bits(),
                ret,
                out
            ));
        }
    }
    for &(pb, ret, out) in SP32 {
        let mut o = f32::from_bits(0xdeadbeef);
        let r = unsafe { fl::setpayloadf(&mut o, f32::from_bits(pb)) };
        if r != ret || o.to_bits() != out {
            div.push(format!(
                "setpayloadf(0x{:08x}): fl=ret{}/0x{:08x} glibc=ret{}/0x{:08x}",
                pb,
                r,
                o.to_bits(),
                ret,
                out
            ));
        }
    }
    for &(pb, ret, out) in SS32 {
        let mut o = f32::from_bits(0xdeadbeef);
        let r = unsafe { fl::setpayloadsigf(&mut o, f32::from_bits(pb)) };
        if r != ret || o.to_bits() != out {
            div.push(format!(
                "setpayloadsigf(0x{:08x}): fl=ret{}/0x{:08x} glibc=ret{}/0x{:08x}",
                pb,
                r,
                o.to_bits(),
                ret,
                out
            ));
        }
    }
    for &(xb, pl) in GP64 {
        let x = f64::from_bits(xb);
        let g = unsafe { fl::getpayload(&x) }.to_bits();
        if g != pl {
            div.push(format!(
                "getpayload(0x{:016x}): fl=0x{:016x} glibc=0x{:016x}",
                xb, g, pl
            ));
        }
    }
    for &(xb, pl) in GP32 {
        let x = f32::from_bits(xb);
        let g = unsafe { fl::getpayloadf(&x) }.to_bits();
        if g != pl {
            div.push(format!(
                "getpayloadf(0x{:08x}): fl=0x{:08x} glibc=0x{:08x}",
                xb, g, pl
            ));
        }
    }
    assert!(
        div.is_empty(),
        "payload divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
