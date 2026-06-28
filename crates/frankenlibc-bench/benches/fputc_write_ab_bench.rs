//! Buffered-write A/B: deployed fl `fputc` (after the single-threaded registry
//! lock-skip in `FastRegistryMutex::lock`) vs host glibc `fputc`, both writing into an
//! `fmemopen("w")` buffer (stays in the stream buffer — no per-char syscall), in ONE
//! process. glibc is loaded via `dlmopen(LM_ID_NEWLM)` so fl's `no_mangle` stdio symbols
//! don't interpose it. Measures the per-char cost the registry lock dominates.
//!
//! Run: `cargo bench -p frankenlibc-bench --features abi-bench --bench fputc_write_ab_bench`

use std::ffi::{CString, c_char, c_int, c_void};
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_abi::stdio_abi as fl;

const N: usize = 4096;

type FmemopenFn = unsafe extern "C" fn(*mut c_void, usize, *const c_char) -> *mut c_void;
type FputcFn = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;
type RewindFn = unsafe extern "C" fn(*mut c_void);

struct Host {
    fmemopen: FmemopenFn,
    fputc: FputcFn,
    rewind: RewindFn,
}

fn host() -> &'static Host {
    static H: OnceLock<Host> = OnceLock::new();
    H.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let g = |n: &[u8]| {
            let s = libc::dlsym(handle, n.as_ptr().cast());
            assert!(!s.is_null(), "dlsym failed");
            s
        };
        Host {
            fmemopen: std::mem::transmute::<*mut c_void, FmemopenFn>(g(b"fmemopen\0")),
            fputc: std::mem::transmute::<*mut c_void, FputcFn>(g(b"fputc\0")),
            rewind: std::mem::transmute::<*mut c_void, RewindFn>(g(b"rewind\0")),
        }
    })
}

fn p50(s: &mut [f64]) -> f64 {
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if s.is_empty() { return 0.0; }
    let r = 0.5 * (s.len() - 1) as f64;
    let (lo, hi) = (r.floor() as usize, r.ceil() as usize);
    s[lo] * (1.0 - (r - lo as f64)) + s[hi] * (r - lo as f64)
}

fn bench(c: &mut Criterion) {
    let mode = CString::new("w").unwrap();

    let mut fl_buf = vec![0u8; N + 1];
    let fl_fp = unsafe { fl::fmemopen(fl_buf.as_mut_ptr() as *mut c_void, N, mode.as_ptr()) };
    assert!(!fl_fp.is_null(), "fl::fmemopen NULL");

    let h = host();
    let mut g_buf = vec![0u8; N + 1];
    let g_fp = unsafe { (h.fmemopen)(g_buf.as_mut_ptr() as *mut c_void, N, mode.as_ptr()) };
    assert!(!g_fp.is_null(), "glibc fmemopen NULL");

    let fl_once = || {
        unsafe { fl::rewind(fl_fp) };
        let mut s = 0i64;
        for _ in 0..N { s += unsafe { fl::fputc(b'x' as c_int, fl_fp) } as i64; }
        s
    };
    let g_once = || {
        unsafe { (h.rewind)(g_fp) };
        let mut s = 0i64;
        for _ in 0..N { s += unsafe { (h.fputc)(b'x' as c_int, g_fp) } as i64; }
        s
    };

    for _ in 0..50 { black_box(fl_once()); black_box(g_once()); }
    let mut fs = Vec::new();
    let mut gs = Vec::new();
    for _ in 0..200 {
        let t = Instant::now(); black_box(fl_once()); fs.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / N as f64);
        let t = Instant::now(); black_box(g_once()); gs.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / N as f64);
    }
    let (flp, glp) = (p50(&mut fs), p50(&mut gs));
    println!("FPUTC_WRITE fl_p50_ns_per_char={flp:.4} glibc_p50_ns_per_char={glp:.4} ratio={:.3}", flp / glp);

    let mut grp = c.benchmark_group("fputc_write_4096");
    grp.sample_size(30);
    grp.bench_function("frankenlibc_abi", |b| b.iter(|| black_box(fl_once())));
    grp.bench_function("glibc", |b| b.iter(|| black_box(g_once())));
    grp.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
