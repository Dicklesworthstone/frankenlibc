//! Same-process A/B for wcschr SIMD width: NARROW (8-lane u32 = 32 B, glibc's
//! AVX2 granularity) vs WIDE (32-lane u32 = 128 B, fl's current find tier) vs
//! host glibc `wcschr`, on SHORT (typical) and LONG wide strings. The find
//! returns the first `c`-or-NUL position (then wcschr checks it equals `c`).
//!
//! Run: `cargo bench -p frankenlibc-bench --bench wcschr_width_ab_bench`

#![feature(portable_simd)]

use std::ffi::c_int;
use std::hint::black_box;
use std::simd::Simd;
use std::simd::cmp::SimdPartialEq;

use criterion::{Criterion, criterion_group, criterion_main};

unsafe extern "C" {
    fn wcschr(s: *const i32, c: i32) -> *const i32;
}

macro_rules! find_fn {
    ($name:ident, $n:literal) => {
        #[inline(always)]
        fn $name(s: &[u32], c: u32) -> usize {
            let needle = Simd::<u32, $n>::splat(c);
            let zero = Simd::<u32, $n>::splat(0);
            let mut base = 0usize;
            let mut chunks = s.chunks_exact($n);
            for chunk in chunks.by_ref() {
                let v = Simd::<u32, $n>::from_slice(chunk);
                let hit = v.simd_eq(needle) | v.simd_eq(zero);
                let bits = hit.to_bitmask();
                if bits != 0 {
                    return base + bits.trailing_zeros() as usize;
                }
                base += $n;
            }
            for (i, &w) in chunks.remainder().iter().enumerate() {
                if w == c || w == 0 {
                    return base + i;
                }
            }
            s.len()
        }
    };
}
find_fn!(find_8, 8);
find_fn!(find_32, 32);

fn bench(c: &mut Criterion) {
    // wchar buffers (u32 here; i32 to glibc). 'X' present mid-string, NUL-term.
    let make = |n: usize, at: usize| -> Vec<u32> {
        let mut v = vec![b'a' as u32; n];
        v[at] = b'X' as u32;
        v[n - 1] = 0;
        v
    };
    let cases: &[(&str, usize, usize)] = &[("short60_at30", 60, 30), ("long1024_at500", 1024, 500)];

    for (name, n, at) in cases {
        let s = make(*n, *at);
        // parity: narrow == wide == glibc index
        let nar = find_8(&s, b'X' as u32);
        let wid = find_32(&s, b'X' as u32);
        let g = unsafe { wcschr(s.as_ptr().cast::<i32>(), b'X' as c_int) };
        let goff = ((g as usize) - (s.as_ptr() as usize)) / 4;
        assert_eq!(nar, *at);
        assert_eq!(wid, *at);
        assert_eq!(goff, *at, "glibc wcschr index");

        // deployed core wcschr (find_wide_or_nul_long + check) for the same input
        let dep = frankenlibc_core::string::wide::wcschr(&s, b'X' as u32);
        assert_eq!(dep, Some(*at), "deployed core wcschr");

        let mut grp = c.benchmark_group(format!("wcschr_{name}"));
        grp.bench_function("deployed_core", |b| {
            b.iter(|| {
                black_box(frankenlibc_core::string::wide::wcschr(
                    black_box(&s),
                    b'X' as u32,
                ))
            })
        });
        grp.bench_function("narrow_8lane", |b| {
            b.iter(|| black_box(find_8(black_box(&s), b'X' as u32)))
        });
        grp.bench_function("wide_32lane", |b| {
            b.iter(|| black_box(find_32(black_box(&s), b'X' as u32)))
        });
        grp.bench_function("host_glibc", |b| {
            b.iter(|| {
                black_box(unsafe { wcschr(black_box(s.as_ptr().cast::<i32>()), b'X' as c_int) })
            })
        });
        grp.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
