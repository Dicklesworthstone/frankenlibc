#![cfg(target_os = "linux")]

//! Differential conformance harness for libresolv `ns_get16` / `ns_get32`.
//!
//! These are big-endian byte readers used during DNS message decode.
//! Their value semantics are trivial; the interesting bit is the ABI:
//!   - glibc: `unsigned int ns_get16(const unsigned char *)`
//!   - glibc: `unsigned long ns_get32(const unsigned char *)`
//!
//! fl previously declared u16/u32 returns which left the upper bits of
//! the SysV AMD64 return register undefined for callers expecting
//! u_int / u_long. Both are now widened to match.
//!
//! Filed under [bd-xn6p8] follow-up — extending libresolv parity coverage.

use frankenlibc_abi::resolv_abi as fl;

#[link(name = "resolv")]
unsafe extern "C" {
    fn ns_get16(src: *const u8) -> libc::c_uint;
    fn ns_get32(src: *const u8) -> libc::c_ulong;
}

const NS_GET16_CASES: &[[u8; 2]] = &[
    [0x00, 0x00],
    [0x00, 0x01],
    [0x12, 0x34],
    [0xDE, 0xAD],
    [0xFF, 0xFF],
    [0xFF, 0x00],
    [0x00, 0xFF],
];

const NS_GET16_OFFSET_CASES: &[([u8; 5], usize)] = &[
    ([0xAA, 0x12, 0x34, 0xBB, 0xCC], 1),
    ([0xAA, 0xBB, 0xDE, 0xAD, 0xCC], 2),
    ([0x00, 0xFF, 0x00, 0x7E, 0x55], 2),
];

const NS_GET32_CASES: &[[u8; 4]] = &[
    [0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x01],
    [0xDE, 0xAD, 0xBE, 0xEF],
    [0xFF, 0xFF, 0xFF, 0xFF],
    [0x80, 0x00, 0x00, 0x00], // high-bit-set
    [0x12, 0x34, 0x56, 0x78],
    [0x7F, 0xFF, 0xFF, 0xFF],
    [0xCA, 0xFE, 0xBA, 0xBE],
];

const NS_GET32_OFFSET_CASES: &[([u8; 8], usize)] = &[
    ([0xAA, 0xDE, 0xAD, 0xBE, 0xEF, 0xBB, 0xCC, 0xDD], 1),
    ([0xAA, 0xBB, 0x12, 0x34, 0x56, 0x78, 0xCC, 0xDD], 2),
    ([0x00, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7E, 0x55], 2),
];

#[test]
fn diff_ns_get16_cases() {
    for buf in NS_GET16_CASES {
        let fl_v = unsafe { fl::ns_get16(buf.as_ptr()) };
        let lc_v = unsafe { ns_get16(buf.as_ptr()) };
        assert_eq!(
            fl_v, lc_v,
            "ns_get16 diff for buf={buf:?}: fl={fl_v} glibc={lc_v}"
        );
    }
}

#[test]
fn diff_ns_get16_offset_pointer_cases() {
    for (buf, offset) in NS_GET16_OFFSET_CASES {
        let p = unsafe { buf.as_ptr().add(*offset) };
        let fl_v = unsafe { fl::ns_get16(p) };
        let lc_v = unsafe { ns_get16(p) };
        assert_eq!(
            fl_v, lc_v,
            "ns_get16 offset diff for buf={buf:?} offset={offset}: fl={fl_v} glibc={lc_v}"
        );
    }
}

#[test]
fn diff_ns_get32_cases() {
    for buf in NS_GET32_CASES {
        let fl_v = unsafe { fl::ns_get32(buf.as_ptr()) };
        let lc_v = unsafe { ns_get32(buf.as_ptr()) };
        assert_eq!(
            fl_v, lc_v,
            "ns_get32 diff for buf={buf:?}: fl={fl_v} glibc={lc_v}"
        );
    }
}

#[test]
fn diff_ns_get32_offset_pointer_cases() {
    for (buf, offset) in NS_GET32_OFFSET_CASES {
        let p = unsafe { buf.as_ptr().add(*offset) };
        let fl_v = unsafe { fl::ns_get32(p) };
        let lc_v = unsafe { ns_get32(p) };
        assert_eq!(
            fl_v, lc_v,
            "ns_get32 offset diff for buf={buf:?} offset={offset}: fl={fl_v} glibc={lc_v}"
        );
    }
}

#[test]
fn ns_get_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libresolv ns_get*\",\"reference\":\"glibc\",\"functions\":2,\"ns_get16_cases\":7,\"ns_get16_offset_cases\":3,\"ns_get32_cases\":8,\"ns_get32_offset_cases\":3,\"divergences\":0}}",
    );
}
