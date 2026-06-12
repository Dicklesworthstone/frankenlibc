//! Live-glibc differential gate for the `qsort` large-N integer **radix lane**.
//!
//! Above the comparison-sort fast-lane window (num > 2048) 4-/8-byte integer
//! keys take an LSD radix sort that commits only after verifying the result
//! against the caller's comparator. This gate proves behavior parity is
//! absolute: fl `qsort` output must be byte-identical to glibc `qsort` for
//!   * the natural signed comparator (radix happy path),
//!   * an unsigned comparator (radix verify fails -> generic fallback),
//!   * a descending comparator (radix verify fails -> generic fallback),
//! over element counts spanning the radix threshold and a range of input
//! distributions — random, duplicate-heavy, all-equal, sorted, reverse,
//! small-magnitude (exercises the constant-digit pass skip), and mixed sign
//! (where signed vs unsigned order diverge).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_core::stdlib::qsort as fl_qsort;
use sha2::{Digest, Sha256};
use std::ffi::c_void;

// ---- glibc comparators -----------------------------------------------------
extern "C" fn gl_i32(a: *const c_void, b: *const c_void) -> i32 {
    let (x, y) = unsafe { (*(a as *const i32), *(b as *const i32)) };
    x.cmp(&y) as i32
}
extern "C" fn gl_u32(a: *const c_void, b: *const c_void) -> i32 {
    let (x, y) = unsafe { (*(a as *const u32), *(b as *const u32)) };
    x.cmp(&y) as i32
}
extern "C" fn gl_i32_desc(a: *const c_void, b: *const c_void) -> i32 {
    let (x, y) = unsafe { (*(a as *const i32), *(b as *const i32)) };
    y.cmp(&x) as i32
}
extern "C" fn gl_i64(a: *const c_void, b: *const c_void) -> i32 {
    let (x, y) = unsafe { (*(a as *const i64), *(b as *const i64)) };
    x.cmp(&y) as i32
}
extern "C" fn gl_u64(a: *const c_void, b: *const c_void) -> i32 {
    let (x, y) = unsafe { (*(a as *const u64), *(b as *const u64)) };
    x.cmp(&y) as i32
}
extern "C" fn gl_i64_desc(a: *const c_void, b: *const c_void) -> i32 {
    let (x, y) = unsafe { (*(a as *const i64), *(b as *const i64)) };
    y.cmp(&x) as i32
}

// ---- fl comparators --------------------------------------------------------
fn fl_i32(a: &[u8], b: &[u8]) -> i32 {
    i32::from_ne_bytes(a.try_into().unwrap()).cmp(&i32::from_ne_bytes(b.try_into().unwrap())) as i32
}
fn fl_u32(a: &[u8], b: &[u8]) -> i32 {
    u32::from_ne_bytes(a.try_into().unwrap()).cmp(&u32::from_ne_bytes(b.try_into().unwrap())) as i32
}
fn fl_i32_desc(a: &[u8], b: &[u8]) -> i32 {
    i32::from_ne_bytes(b.try_into().unwrap()).cmp(&i32::from_ne_bytes(a.try_into().unwrap())) as i32
}
fn fl_i64(a: &[u8], b: &[u8]) -> i32 {
    i64::from_ne_bytes(a.try_into().unwrap()).cmp(&i64::from_ne_bytes(b.try_into().unwrap())) as i32
}
fn fl_u64(a: &[u8], b: &[u8]) -> i32 {
    u64::from_ne_bytes(a.try_into().unwrap()).cmp(&u64::from_ne_bytes(b.try_into().unwrap())) as i32
}
fn fl_i64_desc(a: &[u8], b: &[u8]) -> i32 {
    i64::from_ne_bytes(b.try_into().unwrap()).cmp(&i64::from_ne_bytes(a.try_into().unwrap())) as i32
}

/// Pure splitmix64 of `(seed, i)` — deterministic per index, no mutable state.
fn mix(seed: u64, i: usize) -> u64 {
    let mut z = seed.wrapping_add((i as u64).wrapping_mul(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

type GlCmp = extern "C" fn(*const c_void, *const c_void) -> i32;

/// Sort `bytes_in` with both engines under matching comparators; assert the
/// output bytes are identical. Returns the fl-sorted bytes for golden hashing.
fn check(
    label: &str,
    width: usize,
    bytes_in: &[u8],
    fl_cmp: fn(&[u8], &[u8]) -> i32,
    gl_cmp: GlCmp,
) -> Vec<u8> {
    let n = bytes_in.len() / width;
    let mut fl_buf = bytes_in.to_vec();
    fl_qsort(&mut fl_buf, width, fl_cmp);

    let mut gl_buf = bytes_in.to_vec();
    unsafe { libc::qsort(gl_buf.as_mut_ptr() as *mut c_void, n, width, Some(gl_cmp)); }

    assert_eq!(
        fl_buf, gl_buf,
        "{label}: fl qsort bytes diverge from glibc (width={width}, n={n})"
    );
    fl_buf
}

/// Build the byte image for `n` integers of `width` bytes from a generator
/// producing `i64` values (truncated to `width`).
fn image<G: FnMut(usize) -> i64>(n: usize, width: usize, mut g: G) -> Vec<u8> {
    let mut out = Vec::with_capacity(n * width);
    for i in 0..n {
        let v = g(i);
        let b = v.to_ne_bytes();
        out.extend_from_slice(&b[..width]);
    }
    out
}

#[test]
fn qsort_radix_lane_matches_glibc() {
    // Spans below/at/above the radix threshold (2048) into large N.
    let sizes = [2047usize, 2048, 2049, 3000, 4096, 16384, 65537];
    let mut hasher = Sha256::new();

    for &n in &sizes {
        let seed = 0x9E37_79B9u64 ^ (n as u64);

        // A battery of deterministic, index-pure distributions.
        let dists: Vec<(&str, Box<dyn Fn(usize) -> i64>)> = vec![
            ("rand", Box::new(move |i| mix(seed, i) as i64)),
            ("dups8", Box::new(move |i| (mix(seed ^ 0xABCD, i) % 8) as i64 - 4)),
            ("equal", Box::new(|_| 42i64)),
            ("sorted", Box::new(|i| i as i64 - 1000)),
            ("reverse", Box::new(move |i| (n as i64) - i as i64)),
            ("smallpos", Box::new(move |i| (mix(seed ^ 0x1357, i) % 1000) as i64)),
            ("mixedsign", Box::new(move |i| {
                let m = mix(seed ^ 0x2468, i) as i64;
                if i % 2 == 0 { m } else { m.wrapping_neg() }
            })),
        ];

        for (tag, g) in &dists {
            // width 4 (i32)
            let img4 = image(n, 4, |i| g(i));
            check(&format!("i32/{tag}/n{n}"), 4, &img4, fl_i32, gl_i32);
            check(&format!("u32/{tag}/n{n}"), 4, &img4, fl_u32, gl_u32);
            check(&format!("desc32/{tag}/n{n}"), 4, &img4, fl_i32_desc, gl_i32_desc);
            hasher.update(check(&format!("i32g/{tag}/n{n}"), 4, &img4, fl_i32, gl_i32));

            // width 8 (i64)
            let img8 = image(n, 8, |i| g(i));
            check(&format!("i64/{tag}/n{n}"), 8, &img8, fl_i64, gl_i64);
            check(&format!("u64/{tag}/n{n}"), 8, &img8, fl_u64, gl_u64);
            check(&format!("desc64/{tag}/n{n}"), 8, &img8, fl_i64_desc, gl_i64_desc);
            hasher.update(check(&format!("i64g/{tag}/n{n}"), 8, &img8, fl_i64, gl_i64));
        }
    }

    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("qsort radix-lane golden sha256: {hex}");
}
