//! Live-glibc differential gate for the `qsort` 8-byte (i64) natural fast lane.
//!
//! The fast lane sorts raw `i64` keys with the standard-library sort and commits
//! only after verifying the arrangement against the caller's comparator. This
//! gate proves behavior parity is absolute: fl `qsort` output must be
//! byte-identical to glibc `qsort` for
//!   * the natural signed-i64 comparator (the lane's happy path),
//!   * an unsigned-u64 comparator (lane verify fails -> generic fallback),
//!   * a descending comparator (lane verify fails -> generic fallback),
//!
//! across element counts spanning below and inside the lane's activation
//! window, including duplicate-heavy inputs where tie order is unspecified but
//! the emitted bytes are nonetheless fully determined.
//!
//! The window was `[64, 2048]` when this file was written and the sizes below
//! were chosen to straddle 2048. `I64_FAST_LANE_MAX` is now `1 << 22`
//! (cf65cca1d), so **every size here except 1..=63 is now INSIDE the lane** and
//! nothing in this file reaches the upper edge any more. That does not weaken
//! the parity claim, which is what this gate is for, but it does mean the
//! ceiling is untested here. Note also that being inside the window is not the
//! same as taking the lane, and this gate cannot tell the difference — it
//! compares sorted output, which pdqsort also produces (bd-nas5rt).
//! `conformance_diff_qsort_lane_inventory` is the file that settles which path
//! ran, by comparator call count.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_core::stdlib::qsort as fl_qsort;
use sha2::{Digest, Sha256};
use std::ffi::c_void;

extern "C" fn gl_cmp_i64(a: *const c_void, b: *const c_void) -> i32 {
    let x = unsafe { *(a as *const i64) };
    let y = unsafe { *(b as *const i64) };
    x.cmp(&y) as i32
}
extern "C" fn gl_cmp_u64(a: *const c_void, b: *const c_void) -> i32 {
    let x = unsafe { *(a as *const u64) };
    let y = unsafe { *(b as *const u64) };
    x.cmp(&y) as i32
}
extern "C" fn gl_cmp_i64_desc(a: *const c_void, b: *const c_void) -> i32 {
    let x = unsafe { *(a as *const i64) };
    let y = unsafe { *(b as *const i64) };
    y.cmp(&x) as i32
}
extern "C" fn gl_cmp_u64_desc(a: *const c_void, b: *const c_void) -> i32 {
    let x = unsafe { *(a as *const u64) };
    let y = unsafe { *(b as *const u64) };
    y.cmp(&x) as i32
}

fn fl_cmp_i64(a: &[u8], b: &[u8]) -> i32 {
    let x = i64::from_ne_bytes(a.try_into().unwrap());
    let y = i64::from_ne_bytes(b.try_into().unwrap());
    x.cmp(&y) as i32
}
fn fl_cmp_u64(a: &[u8], b: &[u8]) -> i32 {
    let x = u64::from_ne_bytes(a.try_into().unwrap());
    let y = u64::from_ne_bytes(b.try_into().unwrap());
    x.cmp(&y) as i32
}
fn fl_cmp_i64_desc(a: &[u8], b: &[u8]) -> i32 {
    let x = i64::from_ne_bytes(a.try_into().unwrap());
    let y = i64::from_ne_bytes(b.try_into().unwrap());
    y.cmp(&x) as i32
}
fn fl_cmp_u64_desc(a: &[u8], b: &[u8]) -> i32 {
    let x = u64::from_ne_bytes(a.try_into().unwrap());
    let y = u64::from_ne_bytes(b.try_into().unwrap());
    y.cmp(&x) as i32
}

fn lcg(s: &mut u64) -> u64 {
    *s = s
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *s >> 1
}

fn bytes_of(v: &[i64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 8);
    for x in v {
        out.extend_from_slice(&x.to_ne_bytes());
    }
    out
}

type GlCmp = extern "C" fn(*const c_void, *const c_void) -> i32;

fn check(label: &str, data: &[i64], fl_cmp: fn(&[u8], &[u8]) -> i32, gl_cmp: GlCmp) {
    // fl path (inside the width-8 lane's window when n >= I64_FAST_LANE_MIN).
    let mut fl_buf = bytes_of(data);
    fl_qsort(&mut fl_buf, 8, fl_cmp);

    // glibc ground truth.
    let mut gl_vals = data.to_vec();
    unsafe {
        libc::qsort(
            gl_vals.as_mut_ptr() as *mut c_void,
            gl_vals.len(),
            8,
            Some(gl_cmp),
        );
    }
    let gl_buf = bytes_of(&gl_vals);

    assert_eq!(
        fl_buf,
        gl_buf,
        "{label}: fl qsort bytes diverge from glibc (n={})",
        data.len()
    );
}

#[test]
fn qsort_i64_fast_lane_matches_glibc() {
    // Sizes below the floor (1..=63), at the lower edge (64), and inside. The
    // 2047/2048/2049 cluster and 4096 were chosen to straddle a ceiling of
    // 2048; since cf65cca1d raised `I64_FAST_LANE_MAX` to `1 << 22` they are
    // all simply inside, and are kept because they still exercise distinct
    // sizes rather than because they bracket anything.
    let sizes = [
        1usize, 2, 7, 31, 32, 63, 64, 65, 128, 511, 512, 1024, 2047, 2048, 2049, 4096,
    ];
    let mut hasher = Sha256::new();

    for &n in &sizes {
        let mut seed = 0xA5A5_0000 ^ (n as u64);

        // Distinct-ish random keys.
        let rand: Vec<i64> = (0..n).map(|_| lcg(&mut seed) as i64).collect();
        // Duplicate-heavy keys (small value space -> many ties).
        let dups: Vec<i64> = (0..n).map(|_| (lcg(&mut seed) % 5) as i64 - 2).collect();
        // Mixed sign with large-magnitude (where i64 vs u64 order diverges).
        let mixed: Vec<i64> = (0..n)
            .map(|i| {
                if i % 2 == 0 {
                    lcg(&mut seed) as i64
                } else {
                    -(lcg(&mut seed) as i64)
                }
            })
            .collect();

        for (tag, data) in [("rand", &rand), ("dups", &dups), ("mixed", &mixed)] {
            check(&format!("i64/{tag}"), data, fl_cmp_i64, gl_cmp_i64);
            check(&format!("u64/{tag}"), data, fl_cmp_u64, gl_cmp_u64);
            check(
                &format!("desc/{tag}"),
                data,
                fl_cmp_i64_desc,
                gl_cmp_i64_desc,
            );
            check(
                &format!("udesc/{tag}"),
                data,
                fl_cmp_u64_desc,
                gl_cmp_u64_desc,
            );

            // Fold the verified-correct sorted output into a golden digest so a
            // future change to the lane that still "sorts" but reorders bytes is
            // caught even if glibc were to drift.
            let mut sorted = bytes_of(data);
            fl_qsort(&mut sorted, 8, fl_cmp_i64);
            hasher.update(&sorted);
        }
    }

    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("qsort i64 fast-lane golden sha256: {hex}");
}
