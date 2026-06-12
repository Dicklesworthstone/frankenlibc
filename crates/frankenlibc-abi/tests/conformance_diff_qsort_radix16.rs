//! Live-glibc differential gate for the `qsort` 2-byte (i16/u16) radix lane.
//!
//! 2-byte integer keys with num > 256 take a 2-pass LSD radix sort that commits
//! only after verifying the result against the caller's comparator. This gate
//! proves behavior parity is absolute: fl `qsort` output must be byte-identical
//! to glibc `qsort` for
//!   * the natural signed i16 comparator (radix happy path),
//!   * an unsigned u16 comparator (radix verify fails -> generic fallback),
//!   * a descending comparator (radix verify fails -> generic fallback),
//! across element counts spanning the 256 threshold into large N, over random,
//! duplicate-heavy, all-equal, sorted, reverse, small-magnitude, and mixed-sign
//! distributions (where signed vs unsigned 16-bit order diverge).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_core::stdlib::qsort as fl_qsort;
use sha2::{Digest, Sha256};
use std::ffi::c_void;

extern "C" fn gl_i16(a: *const c_void, b: *const c_void) -> i32 {
    let (x, y) = unsafe { (*(a as *const i16), *(b as *const i16)) };
    x.cmp(&y) as i32
}
extern "C" fn gl_u16(a: *const c_void, b: *const c_void) -> i32 {
    let (x, y) = unsafe { (*(a as *const u16), *(b as *const u16)) };
    x.cmp(&y) as i32
}
extern "C" fn gl_i16_desc(a: *const c_void, b: *const c_void) -> i32 {
    let (x, y) = unsafe { (*(a as *const i16), *(b as *const i16)) };
    y.cmp(&x) as i32
}
fn fl_i16(a: &[u8], b: &[u8]) -> i32 {
    i16::from_ne_bytes(a.try_into().unwrap()).cmp(&i16::from_ne_bytes(b.try_into().unwrap())) as i32
}
fn fl_u16(a: &[u8], b: &[u8]) -> i32 {
    u16::from_ne_bytes(a.try_into().unwrap()).cmp(&u16::from_ne_bytes(b.try_into().unwrap())) as i32
}
fn fl_i16_desc(a: &[u8], b: &[u8]) -> i32 {
    i16::from_ne_bytes(b.try_into().unwrap()).cmp(&i16::from_ne_bytes(a.try_into().unwrap())) as i32
}

fn mix(seed: u64, i: usize) -> u64 {
    let mut z = seed.wrapping_add((i as u64).wrapping_mul(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

type GlCmp = extern "C" fn(*const c_void, *const c_void) -> i32;

fn check(label: &str, bytes_in: &[u8], fl_cmp: fn(&[u8], &[u8]) -> i32, gl_cmp: GlCmp) -> Vec<u8> {
    let n = bytes_in.len() / 2;
    let mut fl_buf = bytes_in.to_vec();
    fl_qsort(&mut fl_buf, 2, fl_cmp);
    let mut gl_buf = bytes_in.to_vec();
    unsafe { libc::qsort(gl_buf.as_mut_ptr() as *mut c_void, n, 2, Some(gl_cmp)); }
    assert_eq!(fl_buf, gl_buf, "{label}: fl qsort bytes diverge from glibc (n={n})");
    fl_buf
}

fn image<G: Fn(usize) -> i16>(n: usize, g: G) -> Vec<u8> {
    let mut out = Vec::with_capacity(n * 2);
    for i in 0..n {
        out.extend_from_slice(&g(i).to_ne_bytes());
    }
    out
}

#[test]
fn qsort_radix16_lane_matches_glibc() {
    // Spans below/at/above the 256 threshold into large N.
    let sizes = [255usize, 256, 257, 512, 1024, 4096, 65537];
    let mut hasher = Sha256::new();

    for &n in &sizes {
        let seed = 0x51E2_D3C4u64 ^ (n as u64);
        let dists: Vec<(&str, Box<dyn Fn(usize) -> i16>)> = vec![
            ("rand", Box::new(move |i| mix(seed, i) as i16)),
            ("dups8", Box::new(move |i| (mix(seed ^ 0xAB, i) % 8) as i16 - 4)),
            ("equal", Box::new(|_| 1234i16)),
            ("sorted", Box::new(|i| (i as i16).wrapping_sub(5000))),
            ("reverse", Box::new(move |i| (n as i16).wrapping_sub(i as i16))),
            ("smallpos", Box::new(move |i| (mix(seed ^ 0x13, i) % 500) as i16)),
            ("mixedsign", Box::new(move |i| {
                let m = mix(seed ^ 0x24, i) as i16;
                if i % 2 == 0 { m } else { m.wrapping_neg() }
            })),
        ];
        for (tag, g) in &dists {
            let img = image(n, |i| g(i));
            check(&format!("i16/{tag}/n{n}"), &img, fl_i16, gl_i16);
            check(&format!("u16/{tag}/n{n}"), &img, fl_u16, gl_u16);
            check(&format!("desc16/{tag}/n{n}"), &img, fl_i16_desc, gl_i16_desc);
            hasher.update(check(&format!("i16g/{tag}/n{n}"), &img, fl_i16, gl_i16));
        }
    }

    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("qsort radix16-lane golden sha256: {hex}");
}
