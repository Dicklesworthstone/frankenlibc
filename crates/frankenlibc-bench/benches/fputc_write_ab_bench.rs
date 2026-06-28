//! Buffered-write A/B: deployed fl `fputc` (single-threaded registry write-cache fast
//! path) vs host glibc `fputc`, both into a Full-buffered REGULAR FILE stream (fast-path
//! eligible; fmemopen is mem-backed and excluded). Each sample rewinds (untimed, flushes
//! the prior fill) then times N<BUFSIZ fputc so the whole timed loop stays in the buffer
//! (no syscall). glibc via `dlmopen(LM_ID_NEWLM)`. `__libc_single_threaded` is forced on
//! so the single-threaded fast path is measured (criterion may have spawned threads).
//!
//! Run: `cargo bench -p frankenlibc-bench --features abi-bench --bench fputc_write_ab_bench`

use std::ffi::{CString, c_char, c_int, c_void};
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_abi::stdio_abi as fl;

const N: usize = 4000; // < BUFSIZ (8192) so a full sample stays buffered

type FopenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type FputcFn = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;
type RewindFn = unsafe extern "C" fn(*mut c_void);

struct Host {
    fopen: FopenFn,
    fputc: FputcFn,
    rewind: RewindFn,
}

fn host() -> &'static Host {
    static H: OnceLock<Host> = OnceLock::new();
    H.get_or_init(|| unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen failed");
        let g = |n: &[u8]| {
            let s = libc::dlsym(h, n.as_ptr().cast());
            assert!(!s.is_null());
            s
        };
        Host {
            fopen: std::mem::transmute::<*mut c_void, FopenFn>(g(b"fopen\0")),
            fputc: std::mem::transmute::<*mut c_void, FputcFn>(g(b"fputc\0")),
            rewind: std::mem::transmute::<*mut c_void, RewindFn>(g(b"rewind\0")),
        }
    })
}

fn p50(s: &mut [f64]) -> f64 {
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if s.is_empty() {
        return 0.0;
    }
    let r = 0.5 * (s.len() - 1) as f64;
    let (lo, hi) = (r.floor() as usize, r.ceil() as usize);
    s[lo] * (1.0 - (r - lo as f64)) + s[hi] * (r - lo as f64)
}

fn bench(c: &mut Criterion) {
    // Force single-threaded so the deployed write-cache fast path is exercised (criterion
    // may have spawned worker threads which flip fl's __libc_single_threaded to 0).
    frankenlibc_abi::glibc_internal_abi::__libc_single_threaded
        .store(1, std::sync::atomic::Ordering::Release);

    let w = CString::new("w").unwrap();
    let fl_path = CString::new("/tmp/fl_fputc_ab.out").unwrap();
    let g_path = CString::new("/tmp/glibc_fputc_ab.out").unwrap();

    let fl_fp = unsafe { fl::fopen(fl_path.as_ptr(), w.as_ptr()) };
    assert!(!fl_fp.is_null(), "fl::fopen NULL");
    let h = host();
    let g_fp = unsafe { (h.fopen)(g_path.as_ptr(), w.as_ptr()) };
    assert!(!g_fp.is_null(), "glibc fopen NULL");

    // warm the cache + first-fill
    for _ in 0..100 {
        unsafe { fl::rewind(fl_fp) };
        for _ in 0..N {
            unsafe { fl::fputc(b'x' as c_int, fl_fp) };
        }
        unsafe { (h.rewind)(g_fp) };
        for _ in 0..N {
            unsafe { (h.fputc)(b'x' as c_int, g_fp) };
        }
    }

    let mut fs = Vec::new();
    let mut gs = Vec::new();
    for _ in 0..200 {
        unsafe { fl::rewind(fl_fp) };
        let t = Instant::now();
        for _ in 0..N {
            unsafe { fl::fputc(b'x' as c_int, fl_fp) };
        }
        fs.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / N as f64);

        unsafe { (h.rewind)(g_fp) };
        let t = Instant::now();
        for _ in 0..N {
            unsafe { (h.fputc)(b'x' as c_int, g_fp) };
        }
        gs.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / N as f64);
    }
    let (flp, glp) = (p50(&mut fs), p50(&mut gs));
    println!(
        "FPUTC_WRITE fl_p50_ns_per_char={flp:.4} glibc_p50_ns_per_char={glp:.4} ratio={:.3}",
        flp / glp
    );

    let mut grp = c.benchmark_group("fputc_write_buffered");
    grp.sample_size(30);
    grp.bench_function("frankenlibc_abi", |b| {
        b.iter(|| {
            unsafe { fl::rewind(fl_fp) };
            for _ in 0..N {
                black_box(unsafe { fl::fputc(b'x' as c_int, fl_fp) });
            }
        })
    });
    grp.bench_function("glibc", |b| {
        b.iter(|| {
            unsafe { (h.rewind)(g_fp) };
            for _ in 0..N {
                black_box(unsafe { (h.fputc)(b'x' as c_int, g_fp) });
            }
        })
    });
    grp.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
