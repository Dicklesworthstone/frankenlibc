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

// fl's no_mangle fprintf (release bench) interposes this fixed-3-arg declaration of the
// variadic symbol (matching ABI for the fixed args of an `fprintf(fp, "x%d\n", i)` call).
unsafe extern "C" {
    #[link_name = "fprintf"]
    fn fl_fprintf(stream: *mut c_void, fmt: *const c_char, x: c_int) -> c_int;
}

const N: usize = 4000; // < BUFSIZ (8192) so a full sample stays buffered

type FopenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type FputcFn = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;
type FwriteFn = unsafe extern "C" fn(*const c_void, usize, usize, *mut c_void) -> usize;
type FgetcFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type FreadFn = unsafe extern "C" fn(*mut c_void, usize, usize, *mut c_void) -> usize;
type FprintfFn = unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int;
type RewindFn = unsafe extern "C" fn(*mut c_void);

struct Host {
    fopen: FopenFn,
    fputc: FputcFn,
    fwrite: FwriteFn,
    fgetc: FgetcFn,
    fread: FreadFn,
    fprintf: FprintfFn,
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
            fwrite: std::mem::transmute::<*mut c_void, FwriteFn>(g(b"fwrite\0")),
            fgetc: std::mem::transmute::<*mut c_void, FgetcFn>(g(b"fgetc\0")),
            fread: std::mem::transmute::<*mut c_void, FreadFn>(g(b"fread\0")),
            fprintf: std::mem::transmute::<*mut c_void, FprintfFn>(g(b"fprintf\0")),
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

    // fwrite of small 16-byte chunks (overhead-dominated bulk write — fputs/fwrite fast path).
    const CHUNK: usize = 16;
    const M: usize = 250; // 250*16 = 4000 < BUFSIZ
    let buf = [b'y'; CHUNK];
    for _ in 0..100 {
        unsafe { fl::rewind(fl_fp) };
        for _ in 0..M {
            unsafe { fl::fwrite(buf.as_ptr().cast(), 1, CHUNK, fl_fp) };
        }
        unsafe { (h.rewind)(g_fp) };
        for _ in 0..M {
            unsafe { (h.fwrite)(buf.as_ptr().cast(), 1, CHUNK, g_fp) };
        }
    }
    let mut fw = Vec::new();
    let mut gw = Vec::new();
    for _ in 0..200 {
        unsafe { fl::rewind(fl_fp) };
        let t = Instant::now();
        for _ in 0..M {
            unsafe { fl::fwrite(buf.as_ptr().cast(), 1, CHUNK, fl_fp) };
        }
        fw.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / M as f64);
        unsafe { (h.rewind)(g_fp) };
        let t = Instant::now();
        for _ in 0..M {
            unsafe { (h.fwrite)(buf.as_ptr().cast(), 1, CHUNK, g_fp) };
        }
        gw.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / M as f64);
    }
    let (flw, glw) = (p50(&mut fw), p50(&mut gw));
    println!(
        "FWRITE16 fl_p50_ns_per_call={flw:.4} glibc_p50_ns_per_call={glw:.4} ratio={:.3}",
        flw / glw
    );

    // Baseline: disable the fast path (flag=0 ⇒ write_cache_lookup returns None) to measure
    // the slow fwrite path for the same workload, isolating the fast-path self-speedup.
    frankenlibc_abi::glibc_internal_abi::__libc_single_threaded
        .store(0, std::sync::atomic::Ordering::Release);
    for _ in 0..50 {
        unsafe { fl::rewind(fl_fp) };
        for _ in 0..M {
            unsafe { fl::fwrite(buf.as_ptr().cast(), 1, CHUNK, fl_fp) };
        }
    }
    let mut fwb = Vec::new();
    for _ in 0..200 {
        unsafe { fl::rewind(fl_fp) };
        let t = Instant::now();
        for _ in 0..M {
            unsafe { fl::fwrite(buf.as_ptr().cast(), 1, CHUNK, fl_fp) };
        }
        fwb.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / M as f64);
    }
    let flwb = p50(&mut fwb);
    frankenlibc_abi::glibc_internal_abi::__libc_single_threaded
        .store(1, std::sync::atomic::Ordering::Release);
    println!(
        "FWRITE16_BASELINE fl_slow_p50_ns_per_call={flwb:.4} (fast={flw:.4}) self_speedup={:.3}x",
        flwb / flw
    );

    // ---- READ fast path: fgetc over a Full-buffered fd read stream ----
    std::fs::write("/tmp/fl_fgetc_ab.in", vec![b'z'; N]).unwrap();
    std::fs::write("/tmp/glibc_fgetc_ab.in", vec![b'z'; N]).unwrap();
    let r = CString::new("r").unwrap();
    let fl_rpath = CString::new("/tmp/fl_fgetc_ab.in").unwrap();
    let g_rpath = CString::new("/tmp/glibc_fgetc_ab.in").unwrap();
    let fl_rf = unsafe { fl::fopen(fl_rpath.as_ptr(), r.as_ptr()) };
    let g_rf = unsafe { (h.fopen)(g_rpath.as_ptr(), r.as_ptr()) };
    assert!(!fl_rf.is_null() && !g_rf.is_null(), "read fopen NULL");
    let read_one = |fp: *mut c_void, getc: FgetcFn| {
        let mut acc = 0i64;
        for _ in 0..N {
            acc += unsafe { getc(fp) } as i64;
        }
        acc
    };
    for _ in 0..100 {
        unsafe { fl::rewind(fl_rf) };
        read_one(fl_rf, fl::fgetc);
        unsafe { (h.rewind)(g_rf) };
        read_one(g_rf, h.fgetc);
    }
    let mut fr = Vec::new();
    let mut gr = Vec::new();
    for _ in 0..200 {
        unsafe { fl::rewind(fl_rf) };
        let t = Instant::now();
        black_box(read_one(fl_rf, fl::fgetc));
        fr.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / N as f64);
        unsafe { (h.rewind)(g_rf) };
        let t = Instant::now();
        black_box(read_one(g_rf, h.fgetc));
        gr.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / N as f64);
    }
    let (frp, grp_) = (p50(&mut fr), p50(&mut gr));
    println!(
        "FGETC fl_p50_ns_per_char={frp:.4} glibc_p50_ns_per_char={grp_:.4} ratio={:.3}",
        frp / grp_
    );
    // baseline: flag=0 (fast path off)
    frankenlibc_abi::glibc_internal_abi::__libc_single_threaded
        .store(0, std::sync::atomic::Ordering::Release);
    for _ in 0..50 {
        unsafe { fl::rewind(fl_rf) };
        read_one(fl_rf, fl::fgetc);
    }
    let mut frb = Vec::new();
    for _ in 0..200 {
        unsafe { fl::rewind(fl_rf) };
        let t = Instant::now();
        black_box(read_one(fl_rf, fl::fgetc));
        frb.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / N as f64);
    }
    let frbp = p50(&mut frb);
    frankenlibc_abi::glibc_internal_abi::__libc_single_threaded
        .store(1, std::sync::atomic::Ordering::Release);
    println!(
        "FGETC_BASELINE fl_slow_p50_ns_per_char={frbp:.4} (fast={frp:.4}) self_speedup={:.3}x",
        frbp / frp
    );

    // fread of small 16-byte chunks (overhead-dominated bulk read).
    let mut rbuf = [0u8; CHUNK];
    let read16 = |fp: *mut c_void, fr: FreadFn, b: &mut [u8; CHUNK]| {
        let mut acc = 0usize;
        for _ in 0..M {
            acc += unsafe { fr(b.as_mut_ptr().cast(), 1, CHUNK, fp) };
        }
        acc
    };
    for _ in 0..100 {
        unsafe { fl::rewind(fl_rf) };
        read16(fl_rf, fl::fread, &mut rbuf);
        unsafe { (h.rewind)(g_rf) };
        read16(g_rf, h.fread, &mut rbuf);
    }
    let mut frd = Vec::new();
    let mut grd = Vec::new();
    for _ in 0..200 {
        unsafe { fl::rewind(fl_rf) };
        let t = Instant::now();
        read16(fl_rf, fl::fread, &mut rbuf);
        frd.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / M as f64);
        unsafe { (h.rewind)(g_rf) };
        let t = Instant::now();
        read16(g_rf, h.fread, &mut rbuf);
        grd.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / M as f64);
    }
    let (frdp, grdp) = (p50(&mut frd), p50(&mut grd));
    println!(
        "FREAD16 fl_p50_ns_per_call={frdp:.4} glibc_p50_ns_per_call={grdp:.4} ratio={:.3}",
        frdp / grdp
    );
    frankenlibc_abi::glibc_internal_abi::__libc_single_threaded
        .store(0, std::sync::atomic::Ordering::Release);
    for _ in 0..50 {
        unsafe { fl::rewind(fl_rf) };
        read16(fl_rf, fl::fread, &mut rbuf);
    }
    let mut frdb = Vec::new();
    for _ in 0..200 {
        unsafe { fl::rewind(fl_rf) };
        let t = Instant::now();
        read16(fl_rf, fl::fread, &mut rbuf);
        frdb.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / M as f64);
    }
    let frdbp = p50(&mut frdb);
    frankenlibc_abi::glibc_internal_abi::__libc_single_threaded
        .store(1, std::sync::atomic::Ordering::Release);
    println!(
        "FREAD16_BASELINE fl_slow_p50_ns_per_call={frdbp:.4} (fast={frdp:.4}) self_speedup={:.3}x",
        frdbp / frdp
    );

    // fprintf("x%d\n", i) to a Full-buffered file — small formatted write (format + 1 lock).
    let pf = CString::new("x%d\n").unwrap();
    for _ in 0..100 {
        unsafe { fl::rewind(fl_fp) };
        for i in 0..M as c_int {
            unsafe { fl_fprintf(fl_fp, pf.as_ptr(), i) };
        }
        unsafe { (h.rewind)(g_fp) };
        for i in 0..M as c_int {
            unsafe { (h.fprintf)(g_fp, pf.as_ptr(), i) };
        }
    }
    let mut fp_fl = Vec::new();
    let mut fp_g = Vec::new();
    for _ in 0..200 {
        unsafe { fl::rewind(fl_fp) };
        let t = Instant::now();
        for i in 0..M as c_int {
            unsafe { fl_fprintf(fl_fp, pf.as_ptr(), i) };
        }
        fp_fl.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / M as f64);
        unsafe { (h.rewind)(g_fp) };
        let t = Instant::now();
        for i in 0..M as c_int {
            unsafe { (h.fprintf)(g_fp, pf.as_ptr(), i) };
        }
        fp_g.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / M as f64);
    }
    let (pflp, pfgp) = (p50(&mut fp_fl), p50(&mut fp_g));
    println!(
        "FPRINTF fl_p50_ns_per_call={pflp:.4} glibc_p50_ns_per_call={pfgp:.4} ratio={:.3}",
        pflp / pfgp
    );
    frankenlibc_abi::glibc_internal_abi::__libc_single_threaded
        .store(0, std::sync::atomic::Ordering::Release);
    for _ in 0..50 {
        unsafe { fl::rewind(fl_fp) };
        for i in 0..M as c_int {
            unsafe { fl_fprintf(fl_fp, pf.as_ptr(), i) };
        }
    }
    let mut fp_b = Vec::new();
    for _ in 0..200 {
        unsafe { fl::rewind(fl_fp) };
        let t = Instant::now();
        for i in 0..M as c_int {
            unsafe { fl_fprintf(fl_fp, pf.as_ptr(), i) };
        }
        fp_b.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / M as f64);
    }
    let pfbp = p50(&mut fp_b);
    frankenlibc_abi::glibc_internal_abi::__libc_single_threaded
        .store(1, std::sync::atomic::Ordering::Release);
    println!(
        "FPRINTF_BASELINE fl_slow_p50_ns_per_call={pfbp:.4} (fast={pflp:.4}) self_speedup={:.3}x",
        pfbp / pflp
    );

    // Isolation: no-conversion format ("hello\n", 0 args) — pipeline minus %d/va_list extract.
    let pf0 = CString::new("hello\n").unwrap();
    for _ in 0..100 {
        unsafe { fl::rewind(fl_fp) };
        for i in 0..M as c_int {
            unsafe { fl_fprintf(fl_fp, pf0.as_ptr(), i) };
        }
    }
    let mut fp0 = Vec::new();
    for _ in 0..200 {
        unsafe { fl::rewind(fl_fp) };
        let t = Instant::now();
        for i in 0..M as c_int {
            unsafe { fl_fprintf(fl_fp, pf0.as_ptr(), i) };
        }
        fp0.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / M as f64);
    }
    println!("FPRINTF_NOARG fl_p50_ns_per_call={:.4}", p50(&mut fp0));

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
