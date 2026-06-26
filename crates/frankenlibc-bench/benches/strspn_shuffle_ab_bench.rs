//! Same-process A/B for a strspn set-membership lever: OLD (N separate simd_eq,
//! one per set byte — `in_set_mask6` style) vs NEW (Langdale/Lemire 2-shuffle
//! byte classifier: 2 pshufb + AND, independent of set size) vs host glibc
//! `strspn`. All three in ONE process so per-worker load cancels in the ratios.
//!
//! Membership is verified byte-identical between OLD and NEW on every input
//! before timing. ASCII accept sets only (the 8-bit-mask classifier covers bytes
//! 0x00..0x7F; a real impl would route 0x80+ sets to the scalar path).
//!
//! Run: `cargo bench -p frankenlibc-bench --bench strspn_shuffle_ab_bench`

#![feature(portable_simd)]

use std::ffi::c_char;
use std::hint::black_box;
use std::simd::cmp::SimdPartialEq;
use std::simd::Simd;

use criterion::{criterion_group, criterion_main, Criterion};

const L: usize = 16;

unsafe extern "C" {
    fn strspn(s: *const c_char, accept: *const c_char) -> usize;
}

// ---- OLD: N simd_eq per 16-byte chunk (one per set byte). ----
#[inline(always)]
fn member_eq(lanes: Simd<u8, L>, set: &[u8]) -> std::simd::Mask<i8, L> {
    let mut m = lanes.simd_eq(Simd::splat(set[0]));
    for &b in &set[1..] {
        m |= lanes.simd_eq(Simd::splat(b));
    }
    m
}

fn strspn_old(s: &[u8], set: &[u8]) -> usize {
    let mut base = 0;
    let z = Simd::<u8, L>::splat(0);
    while base + L <= s.len() {
        let lanes = Simd::<u8, L>::from_slice(&s[base..base + L]);
        let stop = lanes.simd_eq(z) | !member_eq(lanes, set);
        let bits = stop.to_bitmask();
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += L;
    }
    while base < s.len() && s[base] != 0 && set.contains(&s[base]) {
        base += 1;
    }
    base
}

// ---- NEW: 2-shuffle classifier (Langdale/Lemire). ----
fn build_luts(set: &[u8]) -> (Simd<u8, L>, Simd<u8, L>) {
    let mut lo = [0u8; L];
    let mut hi = [0u8; L];
    for &v in set {
        debug_assert!(v < 0x80, "ASCII-only prototype");
        lo[(v & 0x0F) as usize] |= 1 << (v >> 4);
    }
    for (k, slot) in hi.iter_mut().enumerate().take(8) {
        *slot = 1u8 << k;
    }
    (Simd::from_array(lo), Simd::from_array(hi))
}

#[inline(always)]
fn member_shuffle(
    lanes: Simd<u8, L>,
    lo_lut: Simd<u8, L>,
    hi_lut: Simd<u8, L>,
) -> std::simd::Mask<i8, L> {
    let lo = lanes & Simd::splat(0x0F);
    let hi = (lanes >> Simd::splat(4)) & Simd::splat(0x0F);
    let lo_m = lo_lut.swizzle_dyn(lo);
    let hi_m = hi_lut.swizzle_dyn(hi);
    (lo_m & hi_m).simd_ne(Simd::splat(0))
}

fn strspn_new(s: &[u8], lo_lut: Simd<u8, L>, hi_lut: Simd<u8, L>) -> usize {
    let mut base = 0;
    let z = Simd::<u8, L>::splat(0);
    while base + L <= s.len() {
        let lanes = Simd::<u8, L>::from_slice(&s[base..base + L]);
        let stop = lanes.simd_eq(z) | !member_shuffle(lanes, lo_lut, hi_lut);
        let bits = stop.to_bitmask();
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += L;
    }
    // scalar tail using the same LUTs for byte-identity
    let lo = lo_lut.to_array();
    let hi = hi_lut.to_array();
    while base < s.len() && s[base] != 0 {
        let v = s[base];
        if (lo[(v & 0xF) as usize] & hi[(v >> 4) as usize]) == 0 {
            break;
        }
        base += 1;
    }
    base
}

fn bench(c: &mut Criterion) {
    let set: &[u8] = b"aeiou ";
    // accept-run then a stop char + NUL. Two lengths: short (64) and long (512).
    let make = |n: usize| -> Vec<u8> {
        let mut v = Vec::with_capacity(n + 2);
        let cyc = b"aei ou";
        for i in 0..n {
            v.push(cyc[i % cyc.len()]);
        }
        v.push(b'Z'); // stop (not in set)
        v.push(0);
        v
    };
    let (lo_lut, hi_lut) = build_luts(set);
    let mut set_c = set.to_vec();
    set_c.push(0);

    for n in [64usize, 512] {
        let s = make(n);
        // parity: old == new == glibc
        let o = strspn_old(&s, set);
        let nw = strspn_new(&s, lo_lut, hi_lut);
        let g = unsafe { strspn(s.as_ptr().cast(), set_c.as_ptr().cast()) };
        assert_eq!(o, nw, "old/new mismatch n={n}");
        assert_eq!(o, g, "fl/glibc mismatch n={n}: old={o} glibc={g}");

        let mut grp = c.benchmark_group(format!("strspn_n{n}"));
        grp.bench_function("old_neq", |b| b.iter(|| black_box(strspn_old(black_box(&s), set))));
        grp.bench_function("new_shuffle", |b| {
            b.iter(|| black_box(strspn_new(black_box(&s), lo_lut, hi_lut)))
        });
        grp.bench_function("host_glibc", |b| {
            b.iter(|| black_box(unsafe { strspn(black_box(s.as_ptr().cast()), set_c.as_ptr().cast()) }))
        });
        grp.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
