//! Same-process A/B for the memrchr lever: OLD (128-byte folded skip-probe +
//! re-scan of the flagged block = double load) vs NEW (direct 32-byte reverse
//! SIMD scan, one load per panel) vs host glibc memrchr — all in ONE process so
//! per-worker load cancels in the ratios (defeats rch cross-worker variance).
//!
//! Run: `cargo bench -p frankenlibc-bench --bench memrchr_ab_bench`

#![feature(portable_simd)]

use std::ffi::{c_int, c_void};
use std::hint::black_box;
use std::simd::cmp::SimdPartialEq;
use std::simd::Simd;

use criterion::{criterion_group, criterion_main, Criterion};

const LANES: usize = 32;
const FOLD: usize = 128;
const WORD: usize = 8;

unsafe extern "C" {
    fn memrchr(s: *const c_void, c: c_int, n: usize) -> *const c_void;
}

#[inline]
fn u64_from(chunk: &[u8]) -> u64 {
    u64::from_ne_bytes(chunk[..8].try_into().unwrap())
}
#[inline]
fn has_byte_u64(w: u64, b: u8) -> bool {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGHS: u64 = 0x8080_8080_8080_8080;
    let x = w ^ ONES.wrapping_mul(b as u64);
    (x.wrapping_sub(ONES) & !x & HIGHS) != 0
}

#[inline]
fn fold_has(block: &[u8], needle: u8) -> bool {
    let n = Simd::<u8, LANES>::splat(needle);
    for k in 0..FOLD / LANES {
        let v = Simd::<u8, LANES>::from_slice(&block[k * LANES..k * LANES + LANES]);
        if v.simd_eq(n).to_bitmask() != 0 {
            return true;
        }
    }
    false
}

/// OLD: folded 128-byte skip-probe, then re-scan the flagged block (double load).
fn memrchr_old(hs: &[u8], needle: u8) -> Option<usize> {
    let count = hs.len();
    let mut blocks = hs.rchunks_exact(FOLD);
    let mut end = count;
    for block in blocks.by_ref() {
        if fold_has(block, needle) {
            let mut pe = end;
            for chunk in block.rchunks_exact(LANES) {
                let lanes = Simd::<u8, LANES>::from_slice(chunk);
                let bits = lanes.simd_eq(Simd::splat(needle)).to_bitmask() as u64;
                if bits != 0 {
                    let j = 63 - bits.leading_zeros() as usize;
                    return Some(pe - LANES + j);
                }
                pe -= LANES;
            }
        }
        end -= FOLD;
    }
    let rem = blocks.remainder();
    let mut chunks = rem.rchunks_exact(LANES);
    for chunk in chunks.by_ref() {
        let lanes = Simd::<u8, LANES>::from_slice(chunk);
        let bits = lanes.simd_eq(Simd::splat(needle)).to_bitmask() as u64;
        if bits != 0 {
            let j = 63 - bits.leading_zeros() as usize;
            return Some(end - LANES + j);
        }
        end -= LANES;
    }
    let rem = chunks.remainder();
    let mut w = rem.rchunks_exact(WORD);
    for chunk in w.by_ref() {
        if has_byte_u64(u64_from(chunk), needle) {
            if let Some(j) = chunk.iter().rposition(|&b| b == needle) {
                return Some(end - WORD + j);
            }
        }
        end -= WORD;
    }
    w.remainder().iter().rposition(|&b| b == needle)
}

/// NEW: direct 32-byte reverse scan, one load per panel.
fn memrchr_new(hs: &[u8], needle: u8) -> Option<usize> {
    let count = hs.len();
    let mut end = count;
    let mut chunks = hs.rchunks_exact(LANES);
    for chunk in chunks.by_ref() {
        let lanes = Simd::<u8, LANES>::from_slice(chunk);
        let bits = lanes.simd_eq(Simd::splat(needle)).to_bitmask() as u64;
        if bits != 0 {
            let j = 63 - bits.leading_zeros() as usize;
            return Some(end - LANES + j);
        }
        end -= LANES;
    }
    let rem = chunks.remainder();
    let mut w = rem.rchunks_exact(WORD);
    for chunk in w.by_ref() {
        if has_byte_u64(u64_from(chunk), needle) {
            if let Some(j) = chunk.iter().rposition(|&b| b == needle) {
                return Some(end - WORD + j);
            }
        }
        end -= WORD;
    }
    w.remainder().iter().rposition(|&b| b == needle)
}

fn bench(c: &mut Criterion) {
    // Match-near-front (survey shape): 200 bytes, 'X' at 100 — reverse scan must
    // traverse a flagged block. Also a longer 1024-byte variant, 'X' at 400.
    let cases: &[(&str, usize, usize)] = &[("n200_at100", 200, 100), ("n1024_at400", 1024, 400)];
    for (name, n, at) in cases {
        let mut buf = vec![b'a'; *n];
        buf[*at] = b'X';
        // parity across all three
        let o = memrchr_old(&buf, b'X');
        let nw = memrchr_new(&buf, b'X');
        let g = unsafe { memrchr(buf.as_ptr().cast(), b'X' as c_int, buf.len()) };
        let goff = if g.is_null() { None } else { Some(g as usize - buf.as_ptr() as usize) };
        assert_eq!(o, Some(*at));
        assert_eq!(nw, Some(*at));
        assert_eq!(goff, Some(*at));

        let mut grp = c.benchmark_group(format!("memrchr_{name}"));
        grp.bench_function("old_fold", |b| b.iter(|| black_box(memrchr_old(black_box(&buf), b'X'))));
        grp.bench_function("new_direct", |b| b.iter(|| black_box(memrchr_new(black_box(&buf), b'X'))));
        grp.bench_function("host_glibc", |b| {
            b.iter(|| black_box(unsafe { memrchr(black_box(buf.as_ptr().cast()), b'X' as c_int, buf.len()) }))
        });
        grp.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
