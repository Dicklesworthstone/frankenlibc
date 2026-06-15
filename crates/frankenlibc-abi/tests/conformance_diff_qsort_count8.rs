//! Live-glibc differential gate for the `qsort` 1-byte counting-sort lane.
//!
//! 1-byte keys with num > 256 take a dedicated counting sort (histogram + one
//! memset run per value) that commits only after verifying the result against
//! the caller's comparator. This gate proves behavior parity is absolute: fl
//! `qsort` output must be byte-identical to glibc `qsort` for
//!   * an unsigned-char comparator (unsigned-ascending happy path),
//!   * a signed-char comparator (signed-ascending path: 0x80..=0xFF first),
//!   * a descending comparator (both natural orders fail -> pdqsort fallback),
//!
//! across element counts spanning the 256 threshold into large N, over random,
//! duplicate-heavy, all-equal, sorted, reverse, and few-value distributions.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_core::stdlib::qsort as fl_qsort;
use sha2::{Digest, Sha256};
use std::ffi::c_void;

type DistGen = Box<dyn Fn(usize) -> u8>;

extern "C" fn gl_u8(a: *const c_void, b: *const c_void) -> i32 {
    let (x, y) = unsafe { (*(a as *const u8), *(b as *const u8)) };
    (x as i32) - (y as i32)
}
extern "C" fn gl_i8(a: *const c_void, b: *const c_void) -> i32 {
    let (x, y) = unsafe { (*(a as *const i8), *(b as *const i8)) };
    (x as i32) - (y as i32)
}
extern "C" fn gl_u8_desc(a: *const c_void, b: *const c_void) -> i32 {
    let (x, y) = unsafe { (*(a as *const u8), *(b as *const u8)) };
    (y as i32) - (x as i32)
}
fn fl_u8(a: &[u8], b: &[u8]) -> i32 {
    (a[0] as i32) - (b[0] as i32)
}
fn fl_i8(a: &[u8], b: &[u8]) -> i32 {
    (a[0] as i8 as i32) - (b[0] as i8 as i32)
}
fn fl_u8_desc(a: &[u8], b: &[u8]) -> i32 {
    (b[0] as i32) - (a[0] as i32)
}

fn mix(seed: u64, i: usize) -> u64 {
    let mut z = seed.wrapping_add((i as u64).wrapping_mul(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

type GlCmp = extern "C" fn(*const c_void, *const c_void) -> i32;

fn check(label: &str, bytes_in: &[u8], fl_cmp: fn(&[u8], &[u8]) -> i32, gl_cmp: GlCmp) -> Vec<u8> {
    let n = bytes_in.len();
    let mut fl_buf = bytes_in.to_vec();
    fl_qsort(&mut fl_buf, 1, fl_cmp);
    let mut gl_buf = bytes_in.to_vec();
    unsafe {
        libc::qsort(gl_buf.as_mut_ptr() as *mut c_void, n, 1, Some(gl_cmp));
    }
    assert_eq!(
        fl_buf, gl_buf,
        "{label}: fl qsort bytes diverge from glibc (n={n})"
    );
    fl_buf
}

#[test]
fn qsort_count8_lane_matches_glibc() {
    let sizes = [255usize, 256, 257, 512, 1024, 4096, 65537];
    let mut hasher = Sha256::new();

    for &n in &sizes {
        let seed = 0x2BD3_C4E5u64 ^ (n as u64);
        let dists: Vec<(&str, DistGen)> = vec![
            ("rand", Box::new(move |i| mix(seed, i) as u8)),
            ("dups4", Box::new(move |i| (mix(seed ^ 0xAB, i) % 4) as u8)),
            ("equal", Box::new(|_| 0xA5u8)),
            ("sorted", Box::new(|i| (i & 0xff) as u8)),
            ("reverse", Box::new(move |i| ((n - i) & 0xff) as u8)),
            (
                "signedish",
                Box::new(move |i| (mix(seed ^ 0x13, i) as u8) | 0x80),
            ),
            (
                "twoval",
                Box::new(move |i| {
                    if mix(seed ^ 0x55, i) & 1 == 0 {
                        0x00
                    } else {
                        0xFF
                    }
                }),
            ),
        ];
        for (tag, g) in &dists {
            let img: Vec<u8> = (0..n).map(g.as_ref()).collect();
            check(&format!("u8/{tag}/n{n}"), &img, fl_u8, gl_u8);
            check(&format!("i8/{tag}/n{n}"), &img, fl_i8, gl_i8);
            check(&format!("desc/{tag}/n{n}"), &img, fl_u8_desc, gl_u8_desc);
            hasher.update(check(&format!("u8g/{tag}/n{n}"), &img, fl_u8, gl_u8));
        }
    }

    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("qsort count8-lane golden sha256: {hex}");
}
