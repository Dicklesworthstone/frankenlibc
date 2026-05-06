#![cfg(target_os = "linux")]

//! Metamorphic-property tests for `strtol(3)` / `strtoul(3)` / their
//! `*ll` siblings, exercised against well-formed decimal and hex
//! formattings produced by Rust's own `format!`.
//!
//! These verify FL-internal algebraic invariants without depending on
//! a host-glibc oracle (the differential matrix in
//! `conformance_diff_stdlib_numeric.rs` already covers the diff side).
//! Differential tests fail-close only when our parser diverges from
//! glibc; metamorphic tests fail-close when our own contract drifts —
//! catching regressions where FL changes consistently with glibc but
//! still breaks a documented invariant.
//!
//!   M1 (round-trip identity, base 10):
//!       strtoul(format!("{x}"), base=10) == x  for x: u64
//!   M2 (round-trip identity, base 16):
//!       strtoul(format!("{x:x}"), base=16) == x  for x: u64
//!   M3 (leading-zero invariance, decimal):
//!       strtoul("00000" + s, base=10) == strtoul(s, base=10)
//!   M4 (leading-whitespace skip, POSIX):
//!       strtoul("   " + s, base=10) == strtoul(s, base=10)
//!   M5 (sign symmetry, i64 in [i32::MIN+1 ..= i32::MAX]):
//!       strtol("-" + |x|_str) == -strtol(|x|_str)
//!   M6 (endptr-after-numeric):
//!       For a NUL-terminated decimal string, the captured endptr
//!       points exactly at the terminating NUL byte.
//!
//! The corpus draws 256 PCG32-deterministic u64 samples plus a
//! curated adversarial set (boundary values for u8/u16/u32/u64 and
//! signed siblings). Failures print both the input and the relation.
//!
//! Bead: bd-hoofm.

use std::ffi::{CString, c_char, c_int, c_long};
use std::ptr;

use frankenlibc_abi::stdlib_abi as fl;

/// PCG32 deterministic generator seeded for reproducibility.
struct Pcg32 {
    state: u64,
    inc: u64,
}

impl Pcg32 {
    fn new(seed: u64) -> Self {
        let mut p = Self {
            state: 0,
            inc: (seed << 1) | 1,
        };
        p.next_u32();
        p.state = p.state.wrapping_add(seed);
        p.next_u32();
        p
    }
    fn next_u32(&mut self) -> u32 {
        let oldstate = self.state;
        self.state = oldstate
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(self.inc);
        let xorshifted = (((oldstate >> 18) ^ oldstate) >> 27) as u32;
        let rot = (oldstate >> 59) as u32;
        xorshifted.rotate_right(rot)
    }
    fn next_u64(&mut self) -> u64 {
        ((self.next_u32() as u64) << 32) | (self.next_u32() as u64)
    }
}

fn fl_strtoul(s: &str, base: c_int) -> (u64, isize) {
    let cstr = CString::new(s).expect("test input must not contain NUL");
    let mut endptr: *mut c_char = ptr::null_mut();
    // SAFETY: cstr/end pointers are well-formed; we read endptr offset before drop.
    let v = unsafe { fl::strtoul(cstr.as_ptr(), &mut endptr, base) };
    let off = if endptr.is_null() {
        -1
    } else {
        // SAFETY: endptr came from inside cstr, offset is well-defined.
        unsafe { endptr.offset_from(cstr.as_ptr()) }
    };
    (v, off)
}

fn fl_strtol(s: &str, base: c_int) -> (c_long, isize) {
    let cstr = CString::new(s).expect("test input must not contain NUL");
    let mut endptr: *mut c_char = ptr::null_mut();
    // SAFETY: same as fl_strtoul.
    let v = unsafe { fl::strtol(cstr.as_ptr(), &mut endptr, base) };
    let off = if endptr.is_null() {
        -1
    } else {
        // SAFETY: same as fl_strtoul.
        unsafe { endptr.offset_from(cstr.as_ptr()) }
    };
    (v, off)
}

fn corpus_u64() -> Vec<u64> {
    let mut samples: Vec<u64> = vec![
        0,
        1,
        2,
        7,
        9,
        10,
        15,
        16,
        u8::MAX as u64,
        (u8::MAX as u64) + 1,
        u16::MAX as u64,
        (u16::MAX as u64) + 1,
        u32::MAX as u64,
        (u32::MAX as u64) + 1,
        i32::MAX as u64,
        i32::MIN as i64 as u64, // wraps to high bit set
        i64::MAX as u64,
        u64::MAX,
    ];
    let mut rng = Pcg32::new(0xb1ad_c0ff_ee_15_face);
    for _ in 0..256 {
        samples.push(rng.next_u64());
    }
    samples
}

fn corpus_i64() -> Vec<i64> {
    let mut samples: Vec<i64> = vec![
        0,
        1,
        -1,
        2,
        -2,
        i32::MAX as i64,
        i32::MIN as i64 + 1,
        i64::MAX,
        i64::MIN + 1, // exclude i64::MIN — its absolute value overflows i64
    ];
    let mut rng = Pcg32::new(0xface_b1ad_c0ff_ee15);
    for _ in 0..256 {
        let raw = rng.next_u64();
        let signed = (raw as i64) >> 1; // shrink to avoid i64::MIN edge
        samples.push(signed);
    }
    samples
}

#[test]
fn m1_strtoul_round_trips_base10() {
    for x in corpus_u64() {
        let s = format!("{x}");
        let (v, off) = fl_strtoul(&s, 10);
        assert_eq!(v, x, "M1 base-10 round-trip failed for {x}: got {v}");
        assert_eq!(
            off,
            s.len() as isize,
            "M1 endptr must reach NUL for {s:?}: off={off}, len={}",
            s.len()
        );
    }
}

#[test]
fn m2_strtoul_round_trips_base16() {
    for x in corpus_u64() {
        let s = format!("{x:x}");
        let (v, off) = fl_strtoul(&s, 16);
        assert_eq!(v, x, "M2 base-16 round-trip failed for {x:#x}: got {v:#x}");
        assert_eq!(
            off,
            s.len() as isize,
            "M2 endptr must reach NUL for {s:?}: off={off}, len={}",
            s.len()
        );
    }
}

#[test]
fn m3_leading_zeros_are_invariant_in_base10() {
    for x in corpus_u64() {
        let s = format!("{x}");
        let padded = format!("00000{s}");
        let (v_plain, _) = fl_strtoul(&s, 10);
        let (v_padded, _) = fl_strtoul(&padded, 10);
        assert_eq!(
            v_plain, v_padded,
            "M3 leading-zero invariance failed for {x}: plain={v_plain}, padded={v_padded}"
        );
    }
}

#[test]
fn m4_leading_whitespace_is_skipped_per_posix() {
    for x in corpus_u64() {
        let s = format!("{x}");
        let prefixed = format!("   {s}");
        let (v_plain, _) = fl_strtoul(&s, 10);
        let (v_prefixed, _) = fl_strtoul(&prefixed, 10);
        assert_eq!(
            v_plain, v_prefixed,
            "M4 leading-whitespace skip failed for {x}: plain={v_plain}, prefixed={v_prefixed}"
        );
    }
}

#[test]
fn m5_sign_symmetry_on_in_range_i64() {
    for x in corpus_i64() {
        if x == i64::MIN {
            continue; // |i64::MIN| overflows i64
        }
        let abs_str = format!("{}", x.unsigned_abs());
        let (v_pos, _) = fl_strtol(&abs_str, 10);
        let neg_str = format!("-{abs_str}");
        let (v_neg, _) = fl_strtol(&neg_str, 10);
        // Skip cases where positive overflows (POSIX behavior is to clamp).
        if v_pos == c_long::MAX && x.unsigned_abs() > c_long::MAX as u64 {
            continue;
        }
        assert_eq!(
            v_neg, -v_pos,
            "M5 sign symmetry failed for x={x}: pos={v_pos}, neg={v_neg}"
        );
    }
}

#[test]
fn m6_endptr_lands_on_nul_for_clean_decimal() {
    // For every clean numeric string, endptr points exactly at the
    // terminating NUL — covered already by M1/M2 but exercised here
    // with mixed-length corpus to exclude off-by-one bugs at the
    // 1/2/3/4-digit boundaries.
    for n in [0u64, 9, 10, 99, 100, 999, 1000, 9_999_999, 1_000_000_000] {
        let s = format!("{n}");
        let (_, off) = fl_strtoul(&s, 10);
        assert_eq!(
            off,
            s.len() as isize,
            "M6 endptr off-by-one for {s:?}: off={off}"
        );
    }
}
