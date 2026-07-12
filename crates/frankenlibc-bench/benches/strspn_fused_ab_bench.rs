//! Same-process A/B for the strspn kernel: OLD (4-pass: pre-scan s, pre-scan
//! accept, build bitmap from slice, scan slice — mimics the deployed ABI shape)
//! vs NEW (fused 2-pass glibc-style: build 256-bit bitmap from accept-ptr, then
//! scan s-ptr against it, stopping at the first non-member/NUL — never pre-scans
//! s) vs host glibc `strspn`. All kernels reimplemented in-bench (no fl abi
//! linkage) so the rch rlib cache cannot corrupt it — only within-process ratios.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench strspn_fused_ab_bench`

use std::ffi::c_char;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

unsafe extern "C" {
    fn strspn(s: *const c_char, accept: *const c_char) -> usize;
}

unsafe fn strlen(p: *const u8) -> usize {
    let mut i = 0;
    while unsafe { *p.add(i) } != 0 {
        i += 1;
    }
    i
}

/// OLD: the deployed-ABI shape — pre-scan BOTH strings to lengths, build a bitmap
/// over the accept slice, then scan the s slice. Four passes total (s pre-scan is
/// pure waste: strspn stops at the first non-member, which may be far before NUL).
unsafe fn strspn_old(s: *const u8, accept: *const u8) -> usize {
    let s_len = unsafe { strlen(s) };
    let a_len = unsafe { strlen(accept) };
    let mut bitmap = [0u64; 4];
    for k in 0..a_len {
        let c = unsafe { *accept.add(k) };
        bitmap[(c >> 6) as usize] |= 1u64 << (c & 63);
    }
    let mut i = 0;
    while i < s_len {
        let c = unsafe { *s.add(i) };
        if (bitmap[(c >> 6) as usize] >> (c & 63)) & 1 == 0 {
            break;
        }
        i += 1;
    }
    i
}

/// NEW: fused glibc-style. Build the 256-bit bitmap from accept (one pass, stops
/// at accept's NUL), then scan s against it (one pass, stops at the first byte not
/// in the set — NUL breaks naturally since the NUL bit is never set). No s pre-scan.
unsafe fn strspn_fused(s: *const u8, accept: *const u8) -> usize {
    let mut bitmap = [0u64; 4];
    let mut a = 0usize;
    loop {
        let c = unsafe { *accept.add(a) };
        if c == 0 {
            break;
        }
        bitmap[(c >> 6) as usize] |= 1u64 << (c & 63);
        a += 1;
    }
    let mut i = 0usize;
    loop {
        let c = unsafe { *s.add(i) };
        if (bitmap[(c >> 6) as usize] >> (c & 63)) & 1 == 0 {
            break; // non-member or NUL
        }
        i += 1;
    }
    i
}

fn cs(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn bench(c: &mut Criterion) {
    // (name, s, accept). Mix of full-accept runs and EARLY-mismatch (where the s
    // pre-scan is pure waste) and a long-string early-mismatch.
    let digits = "0123456789";
    let cases: &[(&str, String, &str)] = &[
        ("run16", "aaaaaaaaaaaaaaaaXYZ".into(), "abcdefghijklmnop"),
        (
            "early",
            "Xaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            "abcdefghijklmnop",
        ),
        ("longrun", "a".repeat(256) + "X", "abcdefghijklmnop"),
        ("digits8", "12345678abc".into(), digits),
        (
            "early_long",
            "Z".to_string() + &"a".repeat(512),
            "abcdefghijklmnop",
        ),
    ];
    for (name, s, accept) in cases {
        let sv = cs(s);
        let av = cs(accept);
        let ps = sv.as_ptr();
        let pa = av.as_ptr();
        let o = unsafe { strspn_old(ps, pa) };
        let n = unsafe { strspn_fused(ps, pa) };
        let g = unsafe { strspn(ps.cast(), pa.cast()) };
        assert_eq!(o, n, "old vs fused {name}");
        assert_eq!(o, g, "old vs glibc {name}");

        let mut grp = c.benchmark_group(format!("strspn_{name}"));
        grp.bench_function("old_4pass", |b| {
            b.iter(|| black_box(unsafe { strspn_old(black_box(ps), black_box(pa)) }))
        });
        grp.bench_function("new_fused", |b| {
            b.iter(|| black_box(unsafe { strspn_fused(black_box(ps), black_box(pa)) }))
        });
        grp.bench_function("host_glibc", |b| {
            b.iter(|| black_box(unsafe { strspn(black_box(ps.cast()), black_box(pa.cast())) }))
        });
        grp.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
