//! Same-process A/B for strspn set-membership levers: OLD (N separate simd_eq,
//! one per set byte — `in_set_mask6` style) vs NEW candidates vs host glibc.
//! All variants run in ONE process so per-worker load cancels in the ratios.
//!
//! Membership is verified byte-identical between OLD and NEW on every input
//! before timing. ASCII accept sets only (the 8-bit-mask classifier covers bytes
//! 0x00..0x7F; a real impl would route 0x80+ sets to the scalar path).
//!
//! Run: `cargo bench -p frankenlibc-bench --bench strspn_shuffle_ab_bench`

#![feature(portable_simd)]

use std::ffi::c_char;
use std::hint::black_box;
use std::simd::Simd;
use std::simd::cmp::SimdPartialEq;

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::string::str as core_str;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

const L: usize = 16;
const L32: usize = 32;

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

#[inline(always)]
fn member_eq8_32(lanes: Simd<u8, L32>, set: &[u8; 8]) -> std::simd::Mask<i8, L32> {
    lanes.simd_eq(Simd::splat(set[0]))
        | lanes.simd_eq(Simd::splat(set[1]))
        | lanes.simd_eq(Simd::splat(set[2]))
        | lanes.simd_eq(Simd::splat(set[3]))
        | lanes.simd_eq(Simd::splat(set[4]))
        | lanes.simd_eq(Simd::splat(set[5]))
        | lanes.simd_eq(Simd::splat(set[6]))
        | lanes.simd_eq(Simd::splat(set[7]))
}

fn span_legacy_eq8_32(s: &[u8], set: &[u8; 8], stop_in_set: bool) -> usize {
    let zero = Simd::<u8, L32>::splat(0);
    let mut chunks = s.chunks_exact(L32);
    let mut base = 0usize;

    for chunk in chunks.by_ref() {
        let lanes = Simd::<u8, L32>::from_slice(chunk);
        let member = member_eq8_32(lanes, set);
        let stop = if stop_in_set {
            lanes.simd_eq(zero) | member
        } else {
            lanes.simd_eq(zero) | !member
        };
        let bits = stop.to_bitmask();
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += L32;
    }

    for (j, &byte) in chunks.remainder().iter().enumerate() {
        if byte == 0 || (set.contains(&byte) == stop_in_set) {
            return base + j;
        }
    }

    s.len()
}

fn strspn_legacy_eq8_32(s: &[u8], set: &[u8; 8]) -> usize {
    span_legacy_eq8_32(s, set, false)
}

// ---- NEW: 2-shuffle classifier (Langdale/Lemire). ----
fn build_raw_luts(set: &[u8]) -> ([u8; L], [u8; L]) {
    let mut lo = [0u8; L];
    let mut hi = [0u8; L];
    for (k, &v) in set.iter().enumerate() {
        debug_assert!(k < 8, "prototype supports sets up to 8 bytes");
        let bit = 1u8 << k;
        lo[(v & 0x0F) as usize] |= bit;
        hi[(v >> 4) as usize] |= bit;
    }
    (lo, hi)
}

fn build_luts(set: &[u8]) -> (Simd<u8, L>, Simd<u8, L>) {
    let (lo, hi) = build_raw_luts(set);
    (Simd::from_array(lo), Simd::from_array(hi))
}

fn duplicate_lut(raw: [u8; L]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..L].copy_from_slice(&raw);
    out[L..].copy_from_slice(&raw);
    out
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

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
unsafe fn strspn_ssse3(s: &[u8], lo_lut: [u8; L], hi_lut: [u8; L]) -> usize {
    let mut base = 0usize;
    let zero = _mm_setzero_si128();
    let low_mask = _mm_set1_epi8(0x0F);
    let lo_table = unsafe { _mm_loadu_si128(lo_lut.as_ptr().cast()) };
    let hi_table = unsafe { _mm_loadu_si128(hi_lut.as_ptr().cast()) };

    macro_rules! stop_bits {
        ($offset:expr) => {{
            let lanes = unsafe { _mm_loadu_si128(s.as_ptr().add(base + $offset).cast()) };
            let lo = _mm_and_si128(lanes, low_mask);
            let hi = _mm_and_si128(_mm_srli_epi16(lanes, 4), low_mask);
            let lo_bits = _mm_shuffle_epi8(lo_table, lo);
            let hi_bits = _mm_shuffle_epi8(hi_table, hi);
            let member = _mm_and_si128(lo_bits, hi_bits);
            let nonmember = _mm_cmpeq_epi8(member, zero);
            let nul = _mm_cmpeq_epi8(lanes, zero);
            _mm_movemask_epi8(_mm_or_si128(nonmember, nul)) as u64
        }};
    }

    while base + 64 <= s.len() {
        let bits = stop_bits!(0)
            | (stop_bits!(16) << 16)
            | (stop_bits!(32) << 32)
            | (stop_bits!(48) << 48);
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += 64;
    }

    while base + L <= s.len() {
        let bits = stop_bits!(0);
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += L;
    }

    while base < s.len() && s[base] != 0 {
        let v = s[base];
        if (lo_lut[(v & 0xF) as usize] & hi_lut[(v >> 4) as usize]) == 0 {
            break;
        }
        base += 1;
    }
    base
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn strspn_avx2(
    s: &[u8],
    lo_lut: [u8; L],
    hi_lut: [u8; L],
    lo_lut32: [u8; 32],
    hi_lut32: [u8; 32],
) -> usize {
    let mut base = 0usize;
    let zero = _mm256_setzero_si256();
    let low_mask = _mm256_set1_epi8(0x0F);
    let lo_table = unsafe { _mm256_loadu_si256(lo_lut32.as_ptr().cast()) };
    let hi_table = unsafe { _mm256_loadu_si256(hi_lut32.as_ptr().cast()) };

    macro_rules! stop_bits {
        ($offset:expr) => {{
            let lanes = unsafe { _mm256_loadu_si256(s.as_ptr().add(base + $offset).cast()) };
            let lo = _mm256_and_si256(lanes, low_mask);
            let hi = _mm256_and_si256(_mm256_srli_epi16(lanes, 4), low_mask);
            let lo_bits = _mm256_shuffle_epi8(lo_table, lo);
            let hi_bits = _mm256_shuffle_epi8(hi_table, hi);
            let member = _mm256_and_si256(lo_bits, hi_bits);
            let nonmember = _mm256_cmpeq_epi8(member, zero);
            let nul = _mm256_cmpeq_epi8(lanes, zero);
            _mm256_movemask_epi8(_mm256_or_si256(nonmember, nul)) as u64
        }};
    }

    while base + 128 <= s.len() {
        let bits = (stop_bits!(0) as u128)
            | ((stop_bits!(32) as u128) << 32)
            | ((stop_bits!(64) as u128) << 64)
            | ((stop_bits!(96) as u128) << 96);
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += 128;
    }

    while base + 64 <= s.len() {
        let bits = stop_bits!(0) | (stop_bits!(32) << 32);
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += 64;
    }

    while base + 32 <= s.len() {
        let bits = stop_bits!(0);
        if bits != 0 {
            return base + bits.trailing_zeros() as usize;
        }
        base += 32;
    }

    while base < s.len() && s[base] != 0 {
        let v = s[base];
        if (lo_lut[(v & 0xF) as usize] & hi_lut[(v >> 4) as usize]) == 0 {
            break;
        }
        base += 1;
    }
    base
}

#[cfg(not(target_arch = "x86_64"))]
fn ssse3_available() -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
fn ssse3_available() -> bool {
    std::is_x86_feature_detected!("ssse3")
}

#[cfg(not(target_arch = "x86_64"))]
fn avx2_available() -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
fn avx2_available() -> bool {
    std::is_x86_feature_detected!("avx2")
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
    let (lo_raw, hi_raw) = build_raw_luts(set);
    let lo_raw32 = duplicate_lut(lo_raw);
    let hi_raw32 = duplicate_lut(hi_raw);
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
        if ssse3_available() {
            #[cfg(target_arch = "x86_64")]
            {
                let ssse3 = unsafe { strspn_ssse3(&s, lo_raw, hi_raw) };
                assert_eq!(o, ssse3, "old/ssse3 mismatch n={n}");
            }
        }
        if avx2_available() {
            #[cfg(target_arch = "x86_64")]
            {
                let avx2 = unsafe { strspn_avx2(&s, lo_raw, hi_raw, lo_raw32, hi_raw32) };
                assert_eq!(o, avx2, "old/avx2 mismatch n={n}");
            }
        }

        let mut grp = c.benchmark_group(format!("strspn_n{n}"));
        grp.bench_function("old_neq", |b| {
            b.iter(|| black_box(strspn_old(black_box(&s), set)))
        });
        grp.bench_function("new_shuffle", |b| {
            b.iter(|| black_box(strspn_new(black_box(&s), lo_lut, hi_lut)))
        });
        if ssse3_available() {
            #[cfg(target_arch = "x86_64")]
            grp.bench_function("ssse3_pshufb", |b| {
                b.iter(|| black_box(unsafe { strspn_ssse3(black_box(&s), lo_raw, hi_raw) }))
            });
        }
        if avx2_available() {
            #[cfg(target_arch = "x86_64")]
            grp.bench_function("avx2_pshufb", |b| {
                b.iter(|| {
                    black_box(unsafe {
                        strspn_avx2(black_box(&s), lo_raw, hi_raw, lo_raw32, hi_raw32)
                    })
                })
            });
        }
        grp.bench_function("host_glibc", |b| {
            b.iter(|| {
                black_box(unsafe { strspn(black_box(s.as_ptr().cast()), set_c.as_ptr().cast()) })
            })
        });
        grp.finish();
    }

    let span_set: &[u8; 8] = b"abcdefgh";
    let mut span_accept = span_set.to_vec();
    span_accept.push(0);
    let mut span_s = vec![b'a'; 4096];
    span_s.push(0);
    assert_eq!(strspn_legacy_eq8_32(&span_s, span_set), 4096);
    assert_eq!(core_str::strspn(&span_s, &span_accept), 4096);
    assert_eq!(
        unsafe { strspn(span_s.as_ptr().cast(), span_accept.as_ptr().cast()) },
        4096
    );

    let mut span8 = c.benchmark_group("strspn_interval8_n4096");
    span8.bench_function("legacy_eq8_32", |b| {
        b.iter(|| black_box(strspn_legacy_eq8_32(black_box(&span_s), span_set)))
    });
    span8.bench_function("core_current", |b| {
        b.iter(|| {
            black_box(core_str::strspn(
                black_box(&span_s),
                black_box(&span_accept),
            ))
        })
    });
    span8.bench_function("host_glibc", |b| {
        b.iter(|| {
            black_box(unsafe {
                strspn(
                    black_box(span_s.as_ptr().cast()),
                    span_accept.as_ptr().cast(),
                )
            })
        })
    });
    span8.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
