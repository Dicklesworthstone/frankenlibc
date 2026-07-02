//! Standalone SINGLE-THREADED probe of the deployed stdio-write fast path (fast_write),
//! which criterion benches cannot observe: write_cache_lookup short-circuits when
//! __libc_single_threaded == 0, and criterion spawns threads. A plain single-threaded
//! main() keeps __libc_single_threaded == 1, so fl's lock-free fast_write path is live.
//!
//! Compares deployed fl fputs vs host glibc fputs (dlmopen), both to an fd-backed
//! /dev/null stream with a 64 KiB _IOFBF buffer (the common full-buffered fd case).
//!
//! Run: cargo run --release --example stdio_st_probe --features abi-bench
use std::os::raw::c_char;
use std::time::Instant;

type FopenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut libc::c_void;
type SetvbufFn = unsafe extern "C" fn(*mut libc::c_void, *mut c_char, i32, usize) -> i32;
type FputsFn = unsafe extern "C" fn(*const c_char, *mut libc::c_void) -> i32;
type FflushFn = unsafe extern "C" fn(*mut libc::c_void) -> i32;

fn dl<T: Copy>(h: *mut libc::c_void, n: &[u8]) -> T {
    let p = unsafe { libc::dlsym(h, n.as_ptr().cast()) };
    assert!(!p.is_null(), "dlsym {:?}", std::str::from_utf8(n));
    unsafe { std::mem::transmute_copy::<usize, T>(&(p as usize)) }
}
fn pctl(s: &[f64], q: f64) -> f64 { let mut v=s.to_vec(); v.sort_by(|a,b|a.partial_cmp(b).unwrap()); v[((q*(v.len()-1) as f64).round() as usize).min(v.len()-1)] }

fn main() {
    let st = unsafe { frankenlibc_abi::glibc_internal_abi::__libc_single_threaded.load(std::sync::atomic::Ordering::Acquire) };
    println!("__libc_single_threaded = {st} (1 => fast path live)");

    let h = unsafe { libc::dlmopen(libc::LM_ID_NEWLM, b"libc.so.6\0".as_ptr().cast(), libc::RTLD_LAZY | libc::RTLD_LOCAL) };
    assert!(!h.is_null());
    let g_fopen: FopenFn = dl(h, b"fopen\0");
    let g_setvbuf: SetvbufFn = dl(h, b"setvbuf\0");
    let g_fputs: FputsFn = dl(h, b"fputs\0");
    let g_fflush: FflushFn = dl(h, b"fflush\0");

    use frankenlibc_abi::stdio_abi as fl;
    let path = b"/dev/null\0".as_ptr() as *const c_char;
    let mode = b"w\0".as_ptr() as *const c_char;
    let cap = 1usize << 16;

    let gf = unsafe { g_fopen(path, mode) }; assert!(!gf.is_null());
    unsafe { g_setvbuf(gf, std::ptr::null_mut(), libc::_IOFBF, cap); }
    let ff = unsafe { fl::fopen(path, mode) }; assert!(!ff.is_null());
    unsafe { fl::setvbuf(ff, std::ptr::null_mut(), libc::_IOFBF, cap); }

    let it = 200_000u64;
    for &n in &[8usize, 38, 200] {
        let s: Vec<u8> = std::iter::repeat(b'x').take(n).chain(std::iter::once(0)).collect();
        let sp = s.as_ptr() as *const c_char;
        for _ in 0..1000 { unsafe { fl::fputs(sp, ff); g_fputs(sp, gf); } }
        unsafe { fl::fflush(ff); g_fflush(gf); }
        let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..80 {
            let t = Instant::now(); for _ in 0..it { unsafe { fl::fputs(sp, ff); } } unsafe { fl::fflush(ff); } fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { unsafe { g_fputs(sp, gf); } } unsafe { g_fflush(gf); } gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        let (fp, gp) = (pctl(&fs, 0.5), pctl(&gs, 0.5));
        println!("FPUTS_ST n={n} fl={fp:.2} glibc={gp:.2} fl/glibc={:.3}", fp/gp);
    }

    // Isolate the canonical_stream_id (native lock) cost that the pointer-keyed fast path
    // now skips — same process, so this ns is directly comparable within this run.
    let mut cs = Vec::new();
    for _ in 0..80 {
        let t = Instant::now();
        for _ in 0..it { black_box_usize(unsafe { frankenlibc_abi::stdio_abi::bench_canonical_stream_id_cost(black_box_ptr(ff)) }); }
        cs.push(t.elapsed().as_nanos() as f64 / it as f64);
    }
    println!("CANONICAL_STREAM_ID_COST ns={:.2} (per call; the lock the ptr-keyed fast path skips)", pctl(&cs, 0.5));

    // Definitive same-process A/B: OLD lookup (canonical_stream_id + by-id) vs NEW
    // (pointer-keyed) fast-path fputs, identical fast_write, only the lookup differs.
    let s: Vec<u8> = std::iter::repeat(b'x').take(38).chain(std::iter::once(0)).collect();
    let sp = s.as_ptr() as *const c_char;
    unsafe { assert!(fl::bench_fputs_oldpath(sp, ff)); assert!(fl::bench_fputs_newpath(sp, ff)); fl::fflush(ff); }
    let (mut os, mut ns) = (Vec::new(), Vec::new());
    for _ in 0..120 {
        let t = Instant::now(); for _ in 0..it { unsafe { black_box_bool(fl::bench_fputs_oldpath(sp, ff)); } } unsafe { fl::fflush(ff); } os.push(t.elapsed().as_nanos() as f64 / it as f64);
        let t = Instant::now(); for _ in 0..it { unsafe { black_box_bool(fl::bench_fputs_newpath(sp, ff)); } } unsafe { fl::fflush(ff); } ns.push(t.elapsed().as_nanos() as f64 / it as f64);
    }
    let (op, np) = (pctl(&os, 0.5), pctl(&ns, 0.5));
    println!("FPUTS_LOOKUP_AB old={op:.2} new={np:.2} new/old={:.3} saved={:.2}ns", np/op, op-np);

    // feof A/B: 3-lock old path vs pointer-keyed lock-free new path (same process).
    unsafe { assert_eq!(fl::bench_feof_oldpath(ff), fl::bench_feof_newpath(ff)); }
    let (mut fo, mut fn_) = (Vec::new(), Vec::new());
    for _ in 0..120 {
        let t = Instant::now(); for _ in 0..it { black_box_i32(unsafe { fl::bench_feof_oldpath(black_box_ptr(ff)) }); } fo.push(t.elapsed().as_nanos() as f64 / it as f64);
        let t = Instant::now(); for _ in 0..it { black_box_i32(unsafe { fl::bench_feof_newpath(black_box_ptr(ff)) }); } fn_.push(t.elapsed().as_nanos() as f64 / it as f64);
    }
    let (fop, fnp) = (pctl(&fo, 0.5), pctl(&fn_, 0.5));
    println!("FEOF_AB old={fop:.2} new={fnp:.2} new/old={:.3} saved={:.2}ns", fnp/fop, fop-fnp);
}

#[inline(never)]
fn black_box_i32(v: i32) -> i32 { std::hint::black_box(v) }

#[inline(never)]
fn black_box_bool(v: bool) -> bool { std::hint::black_box(v) }

#[inline(never)]
fn black_box_usize(v: usize) -> usize { std::hint::black_box(v) }
#[inline(never)]
fn black_box_ptr(v: *mut libc::c_void) -> *mut libc::c_void { std::hint::black_box(v) }
