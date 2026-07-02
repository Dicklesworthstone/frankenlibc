//! Fused strstr A/B: deployed FrankenLibC vs host glibc, untracked (mmap'd) haystack.
//!
//! The fused page-chunked strstr returns at the first match without pre-scanning the
//! whole haystack (glibc's shape); the old path did a full scan_c_string(haystack)
//! pass THEN memmem. Two regimes: EARLY (match near the start of a long haystack — the
//! pre-scan was pure waste) and ABSENT (needle not present — full scan either way).
//!
//! Haystack is mmap'd so `known_remaining` is None → the fused path runs.
//! glibc via dlmopen(LM_ID_NEWLM). Default strict mode.

use std::ffi::{c_char, c_void};
use std::sync::OnceLock;
use std::time::Instant;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

type StrstrFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char;

fn host() -> StrstrFn {
    static H: OnceLock<usize> = OnceLock::new();
    let a = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(libc::LM_ID_NEWLM, b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL);
        assert!(!h.is_null());
        libc::dlsym(h, b"strstr\0".as_ptr().cast()) as usize
    });
    unsafe { std::mem::transmute::<usize, StrstrFn>(a) }
}

fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let r = q * (v.len() - 1) as f64;
    let (lo, hi) = (r.floor() as usize, r.ceil() as usize);
    if lo == hi { v[lo] } else { v[lo] * (1.0 - (r - lo as f64)) + v[hi] * (r - lo as f64) }
}

/// mmap a NUL-terminated haystack of `n` 'a' bytes; splice needle "needle!" at `pos`
/// (or nowhere if pos == usize::MAX). Returns the base pointer (leaked; bench-only).
unsafe fn make_hay(n: usize, pos: usize) -> *const c_char {
    let m = libc::mmap(std::ptr::null_mut(), n + 4096,
        libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
    assert_ne!(m, libc::MAP_FAILED);
    let p = m.cast::<u8>();
    for i in 0..n { *p.add(i) = b'a'; }
    if pos != usize::MAX {
        for (i, &b) in b"needle!".iter().enumerate() { *p.add(pos + i) = b; }
    }
    *p.add(n) = 0;
    p.cast()
}

fn bench(c: &mut Criterion) {
    let g = host();
    let needle = b"needle!\0".as_ptr().cast::<c_char>();
    let mut group = c.benchmark_group("strstr_fused");
    group.sample_size(30);

    let cases: &[(&str, usize, usize)] = &[
        ("early_64k@512", 65536, 512),
        ("early_256k@1024", 262144, 1024),
        ("absent_64k", 65536, usize::MAX),
    ];
    for &(label, n, pos) in cases {
        let hay = unsafe { make_hay(n, pos) };
        // byte-identity check
        let fp = unsafe { frankenlibc_abi::string_abi::strstr(hay, needle) };
        let gp = unsafe { g(hay, needle) };
        assert_eq!(fp as usize, gp as usize, "strstr fl!=glibc {label}");

        let it = 500u64;
        let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..80 {
            let t = Instant::now();
            for _ in 0..it { black_box(unsafe { frankenlibc_abi::string_abi::strstr(black_box(hay), black_box(needle)) }); }
            fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now();
            for _ in 0..it { black_box(unsafe { g(black_box(hay), black_box(needle)) }); }
            gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        let (fp, gp) = (pctl(&fs, 0.50), pctl(&gs, 0.50));
        println!("STRSTR_FUSED case={label} fl_p50={fp:.1}ns glibc_p50={gp:.1}ns ratio_fl_over_glibc={:.2}", fp / gp);
    }
    group.bench_function("noop", |b| b.iter(|| black_box(1u64)));
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
