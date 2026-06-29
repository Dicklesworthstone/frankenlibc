//! Same-process A/B for the wide-char membrane fast-path lever. The entire
//! wide-char family (`wcscmp`/`wcschr`/`wcslen`/…) currently pays the full
//! `runtime_policy::decide()` + `observe()` membrane on EVERY call, even in the
//! default strict-passthrough deployed mode — while the narrow string family
//! (`strcmp`) skips it via a `strict_passthrough_active()` fast path. This bench
//! measures the tax: deployed `wcscmp` (full membrane path) vs the pure core
//! scanner `bench_scan_wcscmp_simd` (= what a strict fast path would call,
//! byte-identical result) vs host glibc `wcscmp` (dlmopen-isolated), all in one
//! process so per-worker load cancels in the ratios.
//!
//! Run: `cargo bench -p frankenlibc-bench --features abi-bench --bench wcscmp_membrane_ab_bench`

use std::ffi::c_int;
use std::hint::black_box;
use std::sync::OnceLock;

use criterion::{criterion_group, criterion_main, Criterion};

use frankenlibc_abi::wchar_abi::{bench_scan_wcscmp_simd, wcscmp, wcsspn, wmemchr, wmemset};

type WcscmpFn = unsafe extern "C" fn(*const u32, *const u32) -> c_int;
type WcsspnFn = unsafe extern "C" fn(*const u32, *const u32) -> usize;
type WmemchrFn = unsafe extern "C" fn(*const u32, u32, usize) -> *mut u32;
type WmemsetFn = unsafe extern "C" fn(*mut u32, u32, usize) -> *mut u32;

fn host_sym(name: &[u8]) -> usize {
    unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6");
        let sym = libc::dlsym(handle, name.as_ptr().cast());
        assert!(!sym.is_null(), "resolve glibc symbol");
        sym as usize
    }
}

/// Deployed-fl `wmemchr` (n-bounded fast path now live) vs host glibc at a small
/// `n` where the fixed membrane tax dominates if still present.
fn bench_wmemchr(c: &mut Criterion) {
    static G: OnceLock<usize> = OnceLock::new();
    let glibc: WmemchrFn =
        unsafe { std::mem::transmute::<usize, WmemchrFn>(*G.get_or_init(|| host_sym(b"wmemchr\0"))) };
    for &n in &[8usize, 64] {
        // miss case: needle not present -> full scan of n
        let buf = vec![b'a' as u32; n];
        let p = buf.as_ptr();
        let c0 = b'Z' as u32;
        assert!(unsafe { wmemchr(p, c0, n) }.is_null());
        assert!(unsafe { glibc(p, c0, n) }.is_null());
        let mut grp = c.benchmark_group(format!("wmemchr_miss_{n}"));
        grp.bench_function("fl_deployed", |bb| {
            bb.iter(|| black_box(unsafe { wmemchr(black_box(p), c0, n) }))
        });
        grp.bench_function("host_glibc", |bb| {
            bb.iter(|| black_box(unsafe { glibc(black_box(p), c0, n) }))
        });
        grp.finish();
    }
}

/// Host glibc `wcscmp` via an isolated dlmopen namespace (bypasses fl's
/// interposing no_mangle symbol).
fn host_wcscmp() -> WcscmpFn {
    static HOST: OnceLock<usize> = OnceLock::new();
    let addr = *HOST.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "failed to dlmopen host libc.so.6");
        let sym = libc::dlsym(handle, b"wcscmp\0".as_ptr().cast());
        assert!(!sym.is_null(), "failed to resolve host glibc wcscmp");
        sym as usize
    });
    unsafe { std::mem::transmute::<usize, WcscmpFn>(addr) }
}

/// Host glibc `wcsspn` via the same isolated dlmopen namespace.
fn host_wcsspn() -> WcsspnFn {
    static HOST: OnceLock<usize> = OnceLock::new();
    let addr = *HOST.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "failed to dlmopen host libc.so.6");
        let sym = libc::dlsym(handle, b"wcsspn\0".as_ptr().cast());
        assert!(!sym.is_null(), "failed to resolve host glibc wcsspn");
        sym as usize
    });
    unsafe { std::mem::transmute::<usize, WcsspnFn>(addr) }
}

/// Deployed-fl `wcsspn` (fast path now live) vs host glibc — short string where
/// the fixed membrane tax would dominate if still present. Confirms the tax is
/// gone (fl ≈ glibc + small core delta, not glibc + ~9ns).
fn bench_wcsspn(c: &mut Criterion) {
    let glibc = host_wcsspn();
    let accept = wstr_set(); // "abcdef\0"
    for &n in &[4usize, 16] {
        let s = wstr(n);
        let pa = s.as_ptr();
        let pset = accept.as_ptr();
        assert_eq!(unsafe { wcsspn(pa, pset) }, n);
        assert_eq!(unsafe { glibc(pa, pset) }, n);
        let mut grp = c.benchmark_group(format!("wcsspn_eq_{n}"));
        grp.bench_function("fl_deployed", |bb| {
            bb.iter(|| black_box(unsafe { wcsspn(black_box(pa), black_box(pset)) }))
        });
        grp.bench_function("host_glibc", |bb| {
            bb.iter(|| black_box(unsafe { glibc(black_box(pa), black_box(pset)) }))
        });
        grp.finish();
    }
}

/// Accept set "abcdef" (all 'a' inputs are fully spanned).
fn wstr_set() -> Vec<u32> {
    let mut v: Vec<u32> = "abcdef".chars().map(|c| c as u32).collect();
    v.push(0);
    v
}

/// Build a NUL-terminated wide string of `n` 'a' wchars.
fn wstr(n: usize) -> Vec<u32> {
    let mut v = vec![b'a' as u32; n];
    v.push(0);
    v
}

fn bench(c: &mut Criterion) {
    let glibc = host_wcscmp();
    // Equal strings of length N (full scan to shared NUL — exercises the kernel
    // and the per-call membrane tax). The tax is fixed-cost per call, so short
    // strings show it most prominently.
    for &n in &[2usize, 4, 8, 16, 32, 64] {
        let a = wstr(n);
        let b = wstr(n);
        let pa = a.as_ptr();
        let pb = b.as_ptr();
        // parity across all three
        assert_eq!(unsafe { wcscmp(pa, pb) }, 0);
        assert_eq!(unsafe { bench_scan_wcscmp_simd(pa, pb, usize::MAX) }, 0);
        assert_eq!(unsafe { glibc(pa, pb) }, 0);

        let mut grp = c.benchmark_group(format!("wcscmp_eq_{n}"));
        grp.bench_function("fl_full_membrane", |bb| {
            bb.iter(|| black_box(unsafe { wcscmp(black_box(pa), black_box(pb)) }))
        });
        grp.bench_function("fl_core_fastpath", |bb| {
            bb.iter(|| {
                black_box(unsafe { bench_scan_wcscmp_simd(black_box(pa), black_box(pb), usize::MAX) })
            })
        });
        grp.bench_function("host_glibc", |bb| {
            bb.iter(|| black_box(unsafe { glibc(black_box(pa), black_box(pb)) }))
        });
        grp.finish();
    }
}

/// Deployed-fl `wmemset` (fast path now live) vs host glibc at small `n` where
/// the fixed membrane tax dominates if still present.
fn bench_wmemset(c: &mut Criterion) {
    static G: OnceLock<usize> = OnceLock::new();
    let glibc: WmemsetFn =
        unsafe { std::mem::transmute::<usize, WmemsetFn>(*G.get_or_init(|| host_sym(b"wmemset\0"))) };
    for &n in &[4usize, 32] {
        let mut a = vec![0u32; n];
        let mut b = vec![0u32; n];
        let pa = a.as_mut_ptr();
        let pb = b.as_mut_ptr();
        unsafe { wmemset(pa, 0x41, n) };
        unsafe { glibc(pb, 0x41, n) };
        assert_eq!(a, b);
        let mut grp = c.benchmark_group(format!("wmemset_{n}"));
        grp.bench_function("fl_deployed", |bb| {
            bb.iter(|| black_box(unsafe { wmemset(black_box(pa), 0x41, n) }))
        });
        grp.bench_function("host_glibc", |bb| {
            bb.iter(|| black_box(unsafe { glibc(black_box(pb), 0x41, n) }))
        });
        grp.finish();
    }
}

criterion_group!(benches, bench, bench_wcsspn, bench_wmemchr, bench_wmemset);
criterion_main!(benches);
