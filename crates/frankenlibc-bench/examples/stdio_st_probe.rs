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

    // Interleave thrash test: single-entry cache should thrash when alternating between
    // TWO streams (each call misses -> canonical_stream_id lock). vs single-stream loop.
    let ff2 = unsafe { fl::fopen(path, mode) }; assert!(!ff2.is_null());
    unsafe { fl::setvbuf(ff2, std::ptr::null_mut(), libc::_IOFBF, cap); }
    let s: Vec<u8> = std::iter::repeat(b'x').take(16).chain(std::iter::once(0)).collect();
    let sp = s.as_ptr() as *const c_char;
    unsafe { fl::fputs(sp, ff); fl::fputs(sp, ff2); fl::fflush(ff); fl::fflush(ff2); }
    let (mut single, mut inter) = (Vec::new(), Vec::new());
    for _ in 0..120 {
        let t = Instant::now(); for _ in 0..it { unsafe { black_box_i32(fl::fputs(sp, ff)); } } unsafe { fl::fflush(ff); } single.push(t.elapsed().as_nanos() as f64 / it as f64);
        let t = Instant::now(); for _ in 0..(it/2) { unsafe { black_box_i32(fl::fputs(sp, ff)); black_box_i32(fl::fputs(sp, ff2)); } } unsafe { fl::fflush(ff); fl::fflush(ff2); } inter.push(t.elapsed().as_nanos() as f64 / it as f64);
    }
    let (sp_, ip_) = (pctl(&single, 0.5), pctl(&inter, 0.5));
    println!("INTERLEAVE single={sp_:.2} two_stream={ip_:.2} inter/single={:.3}", ip_/sp_);

    // fputws: NEW bulk-CONVERT (SIMD wcstombs + one fwrite) vs OLD per-char vs glibc.
    type FputwsFn = unsafe extern "C" fn(*const i32, *mut libc::c_void) -> i32;
    let g_fputws: FputwsFn = dl(h, b"fputws\0");
    for &wn in &[8usize, 16, 64, 200] {
        let ws: Vec<i32> = std::iter::repeat(b'y' as i32).take(wn).chain(std::iter::once(0)).collect();
        let wp = ws.as_ptr();
        unsafe { frankenlibc_abi::wchar_abi::fputws(wp, ff); frankenlibc_abi::wchar_abi::bench_fputws_percall(wp, ff); g_fputws(wp, gf as *mut libc::c_void); fl::fflush(ff); g_fflush(gf); }
        let (mut nb, mut ob, mut gb) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..it { black_box_i32(unsafe { frankenlibc_abi::wchar_abi::fputws(wp, ff) }); } unsafe { fl::fflush(ff); } nb.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { black_box_i32(unsafe { frankenlibc_abi::wchar_abi::bench_fputws_percall(wp, ff) }); } unsafe { fl::fflush(ff); } ob.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { black_box_i32(unsafe { g_fputws(wp, gf as *mut libc::c_void) }); } unsafe { g_fflush(gf); } gb.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        let (np, op, gp) = (pctl(&nb,0.5), pctl(&ob,0.5), pctl(&gb,0.5));
        println!("FPUTWS wn={wn} new={np:.2} old={op:.2} glibc={gp:.2} new/old={:.3} new/glibc={:.3}", np/op, np/gp);
    }

    // fgets lock-elision A/B: a /dev/null "r" stream at EOF. Both hooks return null and
    // run the same fill loop (one read_into_slice->Eof); they differ ONLY in the lookup
    // (old: canonical_stream_id native lock + registry().lock(); new: pointer-keyed). So
    // the delta is the per-line lock overhead fgets pays reading lines from a fopen'd file.
    let rpath = b"/dev/null\0".as_ptr() as *const c_char;
    let rmode = b"r\0".as_ptr() as *const c_char;
    let rf = unsafe { fl::fopen(rpath, rmode) }; assert!(!rf.is_null());
    unsafe { fl::setvbuf(rf, std::ptr::null_mut(), libc::_IOFBF, cap); }
    let mut gbuf = [0u8; 256];
    unsafe { fl::fgetc(rf); } // populate the write cache for rf
    unsafe { assert!(fl::bench_fgets_oldpath(gbuf.as_mut_ptr() as *mut c_char, 256, rf).is_null()); assert!(fl::bench_fgets_newpath(gbuf.as_mut_ptr() as *mut c_char, 256, rf).is_null()); }
    let (mut go, mut gn) = (Vec::new(), Vec::new());
    for _ in 0..120 {
        let t = Instant::now(); for _ in 0..it { std::hint::black_box(unsafe { fl::bench_fgets_oldpath(gbuf.as_mut_ptr() as *mut c_char, 256, rf) }); } go.push(t.elapsed().as_nanos() as f64 / it as f64);
        let t = Instant::now(); for _ in 0..it { std::hint::black_box(unsafe { fl::bench_fgets_newpath(gbuf.as_mut_ptr() as *mut c_char, 256, rf) }); } gn.push(t.elapsed().as_nanos() as f64 / it as f64);
    }
    let (gop, gnp) = (pctl(&go,0.5), pctl(&gn,0.5));
    println!("FGETS_AB old={gop:.2} new={gnp:.2} new/old={:.3} saved={:.2}ns", gnp/gop, gop-gnp);

    // getline PER-LINE over a REAL file (fresh stream; avoids the EOF corner + shared-rf
    // state that made the earlier EOF probe anomalous). Read all lines then rewind, per iter.
    type GetlineFn = unsafe extern "C" fn(*mut *mut c_char, *mut usize, *mut libc::c_void) -> isize;
    type RewindFn = unsafe extern "C" fn(*mut libc::c_void);
    let g_getline: GetlineFn = dl(h, b"getline\0");
    let g_rewind: RewindFn = dl(h, b"rewind\0");
    let nlines = 50usize;
    let content = format!("{}\n", "x".repeat(300)).repeat(nlines);
    std::fs::write("/tmp/fl_getline_probe.txt", &content).unwrap();
    let fpath = b"/tmp/fl_getline_probe.txt\0".as_ptr() as *const c_char;
    let flf = unsafe { fl::fopen(fpath, rmode) }; assert!(!flf.is_null());
    unsafe { fl::setvbuf(flf, std::ptr::null_mut(), libc::_IOFBF, cap); }
    let glf = unsafe { g_fopen(fpath, rmode) }; assert!(!glf.is_null());
    unsafe { g_setvbuf(glf, std::ptr::null_mut(), libc::_IOFBF, cap); }
    let (mut flp, mut glp): (*mut c_char, *mut c_char) = (std::ptr::null_mut(), std::ptr::null_mut());
    let (mut fnc, mut gnc): (usize, usize) = (0, 0);
    // warm
    unsafe { while frankenlibc_abi::stdio_abi::getline(&mut flp, &mut fnc, flf) != -1 {} fl::rewind(flf); while g_getline(&mut glp, &mut gnc, glf) != -1 {} g_rewind(glf as *mut libc::c_void); }
    let iters = 2000u64;
    let (mut fl_v, mut gl_v) = (Vec::new(), Vec::new());
    for _ in 0..80 {
        let t = Instant::now(); for _ in 0..iters { unsafe { while frankenlibc_abi::stdio_abi::getline(&mut flp, &mut fnc, flf) != -1 {} fl::rewind(flf); } } fl_v.push(t.elapsed().as_nanos() as f64 / (iters * nlines as u64) as f64);
        let t = Instant::now(); for _ in 0..iters { unsafe { while g_getline(&mut glp, &mut gnc, glf) != -1 {} g_rewind(glf as *mut libc::c_void); } } gl_v.push(t.elapsed().as_nanos() as f64 / (iters * nlines as u64) as f64);
    }
    let (flpl, glpl) = (pctl(&fl_v,0.5), pctl(&gl_v,0.5));
    println!("GETLINE_PERLINE fl={flpl:.2} glibc={glpl:.2} fl/glibc={:.3} (ns/line incl amortized rewind)", flpl/glpl);

    // Large sequential fread over a 256 KiB file in 4 KiB chunks (exercises the buffered refill
    // path). fl vs glibc, ns per fread call (amortized rewind). Certifies the read path.
    type FreadFn = unsafe extern "C" fn(*mut libc::c_void, usize, usize, *mut libc::c_void) -> usize;
    let g_fread: FreadFn = dl(h, b"fread\0");
    let big = vec![b'z'; 256 * 1024];
    std::fs::write("/tmp/fl_fread_probe.bin", &big).unwrap();
    let bpath = b"/tmp/fl_fread_probe.bin\0".as_ptr() as *const c_char;
    let flr = unsafe { fl::fopen(bpath, rmode) }; assert!(!flr.is_null());
    unsafe { fl::setvbuf(flr, std::ptr::null_mut(), libc::_IOFBF, cap); }
    let gr = unsafe { g_fopen(bpath, rmode) }; assert!(!gr.is_null());
    unsafe { g_setvbuf(gr, std::ptr::null_mut(), libc::_IOFBF, cap); }
    let mut chunk = vec![0u8; 4096];
    let chunks_per = (256 * 1024) / 4096u64; // 64
    let riter = 400u64;
    let (mut frv, mut grv) = (Vec::new(), Vec::new());
    for _ in 0..80 {
        let t = Instant::now(); for _ in 0..riter { unsafe { while frankenlibc_abi::stdio_abi::fread(chunk.as_mut_ptr().cast(), 1, 4096, flr) == 4096 {} fl::rewind(flr); } } frv.push(t.elapsed().as_nanos() as f64 / (riter * chunks_per) as f64);
        let t = Instant::now(); for _ in 0..riter { unsafe { while g_fread(chunk.as_mut_ptr().cast(), 1, 4096, gr) == 4096 {} g_rewind(gr as *mut libc::c_void); } } grv.push(t.elapsed().as_nanos() as f64 / (riter * chunks_per) as f64);
    }
    let (frp, grp) = (pctl(&frv,0.5), pctl(&grv,0.5));
    println!("FREAD_4K fl={frp:.2} glibc={grp:.2} fl/glibc={:.3} (ns per 4KiB fread)", frp/grp);

    // Large sequential fwrite to /dev/null in 4 KiB chunks (exercises the buffered write +
    // flush path). fl vs glibc, ns per fwrite call. Certifies the write path.
    type FwriteFn = unsafe extern "C" fn(*const libc::c_void, usize, usize, *mut libc::c_void) -> usize;
    let g_fwrite: FwriteFn = dl(h, b"fwrite\0");
    let src4k = vec![b'w'; 4096];
    let wchunks = 64u64;
    let witer = 400u64;
    let (mut fwv, mut gwv) = (Vec::new(), Vec::new());
    for _ in 0..80 {
        let t = Instant::now(); for _ in 0..witer { for _ in 0..wchunks { unsafe { std::hint::black_box(frankenlibc_abi::stdio_abi::fwrite(src4k.as_ptr().cast(), 1, 4096, ff)); } } unsafe { fl::fflush(ff); } } fwv.push(t.elapsed().as_nanos() as f64 / (witer * wchunks) as f64);
        let t = Instant::now(); for _ in 0..witer { for _ in 0..wchunks { unsafe { std::hint::black_box(g_fwrite(src4k.as_ptr().cast(), 1, 4096, gf)); } } unsafe { g_fflush(gf); } } gwv.push(t.elapsed().as_nanos() as f64 / (witer * wchunks) as f64);
    }
    let (fwp, gwp) = (pctl(&fwv,0.5), pctl(&gwv,0.5));
    println!("FWRITE_4K fl={fwp:.2} glibc={gwp:.2} fl/glibc={:.3} (ns per 4KiB fwrite)", fwp/gwp);

    // wcstol: fl (allocates project_wide_ascii Vec per call) vs glibc. Short numeric wide str.
    type WcstolFn = unsafe extern "C" fn(*const i32, *mut *mut i32, i32) -> i64;
    let g_wcstol: WcstolFn = dl(h, b"wcstol\0");
    let wnum: Vec<i32> = [b'1',b'2',b'3',b'4',b'5',b'6',b'7',b'8',0].iter().map(|&b| b as i32).collect();
    let wp2 = wnum.as_ptr();
    let (mut flw, mut glw) = (Vec::new(), Vec::new());
    let wit = 200_000u64;
    for _ in 0..100 {
        let t = Instant::now(); for _ in 0..wit { black_box_i64(unsafe { frankenlibc_abi::wchar_abi::wcstol(wp2, std::ptr::null_mut(), 10) }); } flw.push(t.elapsed().as_nanos() as f64 / wit as f64);
        let t = Instant::now(); for _ in 0..wit { black_box_i64(unsafe { g_wcstol(wp2, std::ptr::null_mut(), 10) }); } glw.push(t.elapsed().as_nanos() as f64 / wit as f64);
    }
    let (flwp, glwp) = (pctl(&flw,0.5), pctl(&glw,0.5));
    println!("WCSTOL fl={flwp:.2} glibc={glwp:.2} fl/glibc={:.3}", flwp/glwp);

    // qsort: fl (pdqsort) vs glibc (introsort), same array + comparator, dlmopen. Reset the
    // array from a master each sort (a shuffled-but-fixed permutation) so both sort identical work.
    type CmpFn = unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> i32;
    type QsortFn = unsafe extern "C" fn(*mut libc::c_void, usize, usize, CmpFn);
    unsafe extern "C" fn cmp_i32(a: *const libc::c_void, b: *const libc::c_void) -> i32 {
        let (x, y) = unsafe { (*(a as *const i32), *(b as *const i32)) };
        (x > y) as i32 - (x < y) as i32
    }
    let g_qsort: QsortFn = dl(h, b"qsort\0");
    let nq = 1024usize;
    // Deterministic pseudo-shuffle (no rng): a fixed permutation-ish fill.
    let master: Vec<i32> = (0..nq).map(|i| ((i * 2654435761usize) & 0x7fffffff) as i32).collect();
    let mut arr = master.clone();
    let qit = 2000u64;
    let (mut fqv, mut gqv) = (Vec::new(), Vec::new());
    for _ in 0..80 {
        let t = Instant::now(); for _ in 0..qit { arr.copy_from_slice(&master); unsafe { frankenlibc_abi::stdlib_abi::qsort(arr.as_mut_ptr().cast(), nq, 4, Some(cmp_i32)); } std::hint::black_box(arr[0]); } fqv.push(t.elapsed().as_nanos() as f64 / qit as f64);
        let t = Instant::now(); for _ in 0..qit { arr.copy_from_slice(&master); unsafe { g_qsort(arr.as_mut_ptr().cast(), nq, 4, cmp_i32); } std::hint::black_box(arr[0]); } gqv.push(t.elapsed().as_nanos() as f64 / qit as f64);
    }
    let (fqp, gqp) = (pctl(&fqv,0.5), pctl(&gqv,0.5));
    println!("QSORT_1024 fl={fqp:.2} glibc={gqp:.2} fl/glibc={:.3} (ns/sort incl reset)", fqp/gqp);
    // QSORT_SORTED: already-sorted input — pdqsort has an O(n) pattern-defeating fast path;
    // glibc mergesort still does O(n log n) merges. Valid (real sort work, no const-fold).
    let sorted: Vec<i32> = (0..nq as i32).collect();
    let (mut fsv, mut gsv) = (Vec::new(), Vec::new());
    for _ in 0..80 {
        let t = Instant::now(); for _ in 0..qit { arr.copy_from_slice(&sorted); unsafe { frankenlibc_abi::stdlib_abi::qsort(arr.as_mut_ptr().cast(), nq, 4, Some(cmp_i32)); } std::hint::black_box(arr[0]); } fsv.push(t.elapsed().as_nanos() as f64 / qit as f64);
        let t = Instant::now(); for _ in 0..qit { arr.copy_from_slice(&sorted); unsafe { g_qsort(arr.as_mut_ptr().cast(), nq, 4, cmp_i32); } std::hint::black_box(arr[0]); } gsv.push(t.elapsed().as_nanos() as f64 / qit as f64);
    }
    let (fsp, gsp) = (pctl(&fsv,0.5), pctl(&gsv,0.5));
    println!("QSORT_SORTED fl={fsp:.2} glibc={gsp:.2} fl/glibc={:.3} (ns/sort incl reset)", fsp/gsp);
    // bsearch: fl has NO strict_passthrough fast path -> pays full decide()+observe() per call
    // (unlike memcmp/strlen). Indirect comparator calls prevent const-fold. vs glibc dlmopen.
    type BsearchFn = unsafe extern "C" fn(*const libc::c_void, *const libc::c_void, usize, usize, CmpFn) -> *mut libc::c_void;
    let g_bsearch: BsearchFn = dl(h, b"bsearch\0");
    let mut ssorted: Vec<i32> = (0..nq as i32).collect();
    ssorted.sort();
    let keys: [i32; 4] = [1, 511, 900, 1023];
    let (mut fb, mut gb) = (Vec::new(), Vec::new());
    let bit = 200_000u64;
    for _ in 0..100 {
        let t = Instant::now(); for i in 0..bit { let k = keys[(i & 3) as usize]; black_box_ptr3(unsafe { frankenlibc_abi::stdlib_abi::bsearch((&k as *const i32).cast(), ssorted.as_ptr().cast(), nq, 4, Some(cmp_i32)) }); } fb.push(t.elapsed().as_nanos() as f64 / bit as f64);
        let t = Instant::now(); for i in 0..bit { let k = keys[(i & 3) as usize]; black_box_ptr3(unsafe { g_bsearch((&k as *const i32).cast(), ssorted.as_ptr().cast(), nq, 4, cmp_i32) }); } gb.push(t.elapsed().as_nanos() as f64 / bit as f64);
    }
    println!("BSEARCH fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fb,0.5), pctl(&gb,0.5), pctl(&fb,0.5)/pctl(&gb,0.5));
    // QSORT_SMALL: small sorts (common) — the membrane decide()/observe() dominates pdqsort's
    // few comparisons; the strict fast path should show the biggest relative gain here.
    for &sn in &[8usize, 16, 32] {
        let sm: Vec<i32> = (0..sn).map(|i| ((i * 2654435761usize) & 0x7fffffff) as i32).collect();
        let mut sa = sm.clone();
        let sqit = 4000u64;
        let (mut fqs, mut gqs) = (Vec::new(), Vec::new());
        for _ in 0..80 {
            let t = Instant::now(); for _ in 0..sqit { sa.copy_from_slice(&sm); unsafe { frankenlibc_abi::stdlib_abi::qsort(sa.as_mut_ptr().cast(), sn, 4, Some(cmp_i32)); } std::hint::black_box(sa[0]); } fqs.push(t.elapsed().as_nanos() as f64 / sqit as f64);
            let t = Instant::now(); for _ in 0..sqit { sa.copy_from_slice(&sm); unsafe { g_qsort(sa.as_mut_ptr().cast(), sn, 4, cmp_i32); } std::hint::black_box(sa[0]); } gqs.push(t.elapsed().as_nanos() as f64 / sqit as f64);
        }
        println!("QSORT_SMALL n={sn} fl={:.2} glibc={:.2} fl/glibc={:.3} (incl reset)", pctl(&fqs,0.5), pctl(&gqs,0.5), pctl(&fqs,0.5)/pctl(&gqs,0.5));
    }
    // qsort_r: reentrant sort (thunk comparator). fl vs glibc (GNU qsort_r has arg LAST like fl).
    unsafe extern "C" fn cmp_i32_r(a: *const libc::c_void, b: *const libc::c_void, _arg: *mut libc::c_void) -> i32 {
        let (x, y) = unsafe { (*(a as *const i32), *(b as *const i32)) };
        (x > y) as i32 - (x < y) as i32
    }
    type CmpRFn = unsafe extern "C" fn(*const libc::c_void, *const libc::c_void, *mut libc::c_void) -> i32;
    type QsortRFn = unsafe extern "C" fn(*mut libc::c_void, usize, usize, CmpRFn, *mut libc::c_void);
    let g_qsort_r: QsortRFn = dl(h, b"qsort_r\0");
    {
        let sn = 8usize;
        let sm: Vec<i32> = (0..sn).map(|i| ((i * 2654435761usize) & 0x7fffffff) as i32).collect();
        let mut sa = sm.clone();
        let sqit = 4000u64;
        let (mut fq, mut gq) = (Vec::new(), Vec::new());
        for _ in 0..80 {
            let t = Instant::now(); for _ in 0..sqit { sa.copy_from_slice(&sm); unsafe { frankenlibc_abi::stdlib_abi::qsort_r(sa.as_mut_ptr().cast(), sn, 4, Some(cmp_i32_r), std::ptr::null_mut()); } std::hint::black_box(sa[0]); } fq.push(t.elapsed().as_nanos() as f64 / sqit as f64);
            let t = Instant::now(); for _ in 0..sqit { sa.copy_from_slice(&sm); unsafe { g_qsort_r(sa.as_mut_ptr().cast(), sn, 4, cmp_i32_r, std::ptr::null_mut()); } std::hint::black_box(sa[0]); } gq.push(t.elapsed().as_nanos() as f64 / sqit as f64);
        }
        println!("QSORT_R n=8 fl={:.2} glibc={:.2} fl/glibc={:.3} (incl reset)", pctl(&fq,0.5), pctl(&gq,0.5), pctl(&fq,0.5)/pctl(&gq,0.5));
    }

    // strtod: float parsing, fl vs glibc (dlmopen). Common in config/JSON/scientific input.
    type StrtodFn = unsafe extern "C" fn(*const c_char, *mut *mut c_char) -> f64;
    let g_strtod: StrtodFn = dl(h, b"strtod\0");
    for pat in [b"3.14159\0".as_ref(), b"1.7976931348623157e308\0".as_ref(), b"42\0".as_ref()] {
        let dp = pat.as_ptr() as *const c_char;
        let (mut fdv, mut gdv) = (Vec::new(), Vec::new());
        let dit = 200_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..dit { std::hint::black_box(unsafe { frankenlibc_abi::stdlib_abi::strtod(dp, std::ptr::null_mut()) }); } fdv.push(t.elapsed().as_nanos() as f64 / dit as f64);
            let t = Instant::now(); for _ in 0..dit { std::hint::black_box(unsafe { g_strtod(dp, std::ptr::null_mut()) }); } gdv.push(t.elapsed().as_nanos() as f64 / dit as f64);
        }
        let (fdp, gdp) = (pctl(&fdv,0.5), pctl(&gdv,0.5));
        let s = std::str::from_utf8(&pat[..pat.len()-1]).unwrap();
        println!("STRTOD '{s}' fl={fdp:.2} glibc={gdp:.2} fl/glibc={:.3}", fdp/gdp);
    }

    // strrchr: fl (single-pass last-match) vs glibc (strlen+reverse). Target present once early
    // so both must scan the whole string. Sizes exercise the SIMD scan.
    type StrrchrFn = unsafe extern "C" fn(*const c_char, i32) -> *mut c_char;
    let g_strrchr: StrrchrFn = dl(h, b"strrchr\0");
    for &n in &[64usize, 256, 1024] {
        let mut sv: Vec<u8> = std::iter::repeat(b'a').take(n).collect(); sv[5] = b'b'; sv.push(0);
        let scp = sv.as_ptr() as *const c_char;
        let (mut fsv, mut gsv) = (Vec::new(), Vec::new());
        let sit = 100_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..sit { std::hint::black_box(unsafe { frankenlibc_abi::string_abi::strrchr(scp, b'b' as i32) }); } fsv.push(t.elapsed().as_nanos() as f64 / sit as f64);
            let t = Instant::now(); for _ in 0..sit { std::hint::black_box(unsafe { g_strrchr(scp, b'b' as i32) }); } gsv.push(t.elapsed().as_nanos() as f64 / sit as f64);
        }
        let (fsp, gsp) = (pctl(&fsv,0.5), pctl(&gsv,0.5));
        println!("STRRCHR n={n} fl={fsp:.2} glibc={gsp:.2} fl/glibc={:.3}", fsp/gsp);
    }

    // strchr + memchr: the hottest search fns. Target present once early (full scan). fl vs glibc.
    type StrchrFn = unsafe extern "C" fn(*const c_char, i32) -> *mut c_char;
    type MemchrFn = unsafe extern "C" fn(*const libc::c_void, i32, usize) -> *mut libc::c_void;
    let g_strchr: StrchrFn = dl(h, b"strchr\0");
    let g_memchr: MemchrFn = dl(h, b"memchr\0");
    for &n in &[64usize, 256, 1024] {
        let mut sv: Vec<u8> = std::iter::repeat(b'a').take(n).collect(); sv[n-3] = b'b'; sv.push(0);
        let scp = sv.as_ptr() as *const c_char;
        let (mut fcv, mut gcv, mut fmv, mut gmv) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let cit = 100_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..cit { std::hint::black_box(unsafe { frankenlibc_abi::string_abi::strchr(scp, b'b' as i32) }); } fcv.push(t.elapsed().as_nanos() as f64 / cit as f64);
            let t = Instant::now(); for _ in 0..cit { std::hint::black_box(unsafe { g_strchr(scp, b'b' as i32) }); } gcv.push(t.elapsed().as_nanos() as f64 / cit as f64);
            let t = Instant::now(); for _ in 0..cit { std::hint::black_box(unsafe { frankenlibc_abi::string_abi::memchr(scp.cast(), b'b' as i32, n) }); } fmv.push(t.elapsed().as_nanos() as f64 / cit as f64);
            let t = Instant::now(); for _ in 0..cit { std::hint::black_box(unsafe { g_memchr(scp.cast(), b'b' as i32, n) }); } gmv.push(t.elapsed().as_nanos() as f64 / cit as f64);
        }
        println!("STRCHR n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fcv,0.5), pctl(&gcv,0.5), pctl(&fcv,0.5)/pctl(&gcv,0.5));
        println!("MEMCHR n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fmv,0.5), pctl(&gmv,0.5), pctl(&fmv,0.5)/pctl(&gmv,0.5));
    }

    // strlen: THE hottest libc fn. fl uses 64-byte panels. fl vs glibc, full scan to NUL.
    type StrlenFn = unsafe extern "C" fn(*const c_char) -> usize;
    let g_strlen: StrlenFn = dl(h, b"strlen\0");
    for &n in &[16usize, 64, 256, 1024] {
        let sv: Vec<u8> = std::iter::repeat(b'a').take(n).chain(std::iter::once(0)).collect();
        let scp = sv.as_ptr() as *const c_char;
        let (mut flv2, mut glv2) = (Vec::new(), Vec::new());
        let lit = 200_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..lit { std::hint::black_box(unsafe { frankenlibc_abi::string_abi::strlen(scp) }); } flv2.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { std::hint::black_box(unsafe { g_strlen(scp) }); } glv2.push(t.elapsed().as_nanos() as f64 / lit as f64);
        }
        println!("STRLEN n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&flv2,0.5), pctl(&glv2,0.5), pctl(&flv2,0.5)/pctl(&glv2,0.5));
    }

    // memcpy: deployed no_mangle entry vs glibc (dlmopen). SUSPECT: strict path routes
    // through select_string_simd_dispatch, which returns SCALAR(lane 1) for n<32 (SSE42
    // threshold 32) → the SLOW volatile byte loop, never the raw_overlap_copy small-n win.
    type MemcpyFn = unsafe extern "C" fn(*mut libc::c_void, *const libc::c_void, usize) -> *mut libc::c_void;
    let g_memcpy: MemcpyFn = dl(h, b"memcpy\0");
    for &n in &[8usize, 16, 24, 32, 48, 64, 128] {
        let src: Vec<u8> = (0..n).map(|i| (i & 0xff) as u8).collect();
        let mut dst = vec![0u8; n];
        let (sp, dp) = (src.as_ptr() as *const libc::c_void, dst.as_mut_ptr() as *mut libc::c_void);
        let (mut flv, mut glv) = (Vec::new(), Vec::new());
        let lit = 200_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..lit { std::hint::black_box(unsafe { frankenlibc_abi::string_abi::memcpy(dp, sp, n) }); } flv.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { std::hint::black_box(unsafe { g_memcpy(dp, sp, n) }); } glv.push(t.elapsed().as_nanos() as f64 / lit as f64);
        }
        println!("MEMCPY n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&flv,0.5), pctl(&glv,0.5), pctl(&flv,0.5)/pctl(&glv,0.5));
    }

    // pthread_mutex_lock/unlock: uncontended (single-threaded), the common case. SUSPECT:
    // futex_lock_normal attempts PTHREAD_MUTEX_HTM_SITE.run FIRST → real_htm_supported()
    // FALSE on AMD → ~10ns dead HTM before the compare_exchange that acquires anyway.
    type MtxFn = unsafe extern "C" fn(*mut libc::pthread_mutex_t) -> i32;
    let g_lock: MtxFn = dl(h, b"pthread_mutex_lock\0");
    let g_unlock: MtxFn = dl(h, b"pthread_mutex_unlock\0");
    {
        let mut gm: libc::pthread_mutex_t = unsafe { std::mem::zeroed() };
        let mut fm: libc::pthread_mutex_t = unsafe { std::mem::zeroed() };
        // warm/init both
        for _ in 0..1000 { unsafe {
            frankenlibc_abi::pthread_abi::pthread_mutex_lock(&mut fm); frankenlibc_abi::pthread_abi::pthread_mutex_unlock(&mut fm);
            g_lock(&mut gm); g_unlock(&mut gm);
        }}
        let (mut flv, mut glv) = (Vec::new(), Vec::new());
        let lit = 200_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..lit { unsafe { black_box_i32(frankenlibc_abi::pthread_abi::pthread_mutex_lock(&mut fm)); black_box_i32(frankenlibc_abi::pthread_abi::pthread_mutex_unlock(&mut fm)); } } flv.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { unsafe { black_box_i32(g_lock(&mut gm)); black_box_i32(g_unlock(&mut gm)); } } glv.push(t.elapsed().as_nanos() as f64 / lit as f64);
        }
        println!("MUTEX_LOCKUNLOCK fl={:.2} glibc={:.2} fl/glibc={:.3} (ns/lock+unlock pair)", pctl(&flv,0.5), pctl(&glv,0.5), pctl(&flv,0.5)/pctl(&glv,0.5));
    }

    // memcmp: deployed no_mangle entry vs glibc. SUSPECT: strict path routes through
    // raw_dispatch_memcmp_bytes → select_string_simd_dispatch (~8ns) where the lane only
    // decides >=16 (SIMD) vs <16 (core) — a dead per-call tax like strlen/memcpy.
    type MemcmpFn = unsafe extern "C" fn(*const libc::c_void, *const libc::c_void, usize) -> i32;
    let g_memcmp: MemcmpFn = dl(h, b"memcmp\0");
    for &n in &[8usize, 16, 24, 32, 64, 256] {
        let a: Vec<u8> = (0..n).map(|i| (i & 0xff) as u8).collect();
        let mut b: Vec<u8> = a.clone(); if n > 0 { b[n-1] = b[n-1].wrapping_add(1); } // differ at last byte
        let (ap, bp) = (a.as_ptr() as *const libc::c_void, b.as_ptr() as *const libc::c_void);
        let (mut flv, mut glv) = (Vec::new(), Vec::new());
        let lit = 200_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..lit { black_box_i32(unsafe { frankenlibc_abi::string_abi::memcmp(ap, bp, n) }); } flv.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_i32(unsafe { g_memcmp(ap, bp, n) }); } glv.push(t.elapsed().as_nanos() as f64 / lit as f64);
        }
        println!("MEMCMP n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&flv,0.5), pctl(&glv,0.5), pctl(&flv,0.5)/pctl(&glv,0.5));
    }

    // strcpy + strcmp: deployed no_mangle entries vs glibc. Probe for dead tax / reorderable guard.
    type StrcpyFn = unsafe extern "C" fn(*mut c_char, *const c_char) -> *mut c_char;
    type StrcmpFn = unsafe extern "C" fn(*const c_char, *const c_char) -> i32;
    let g_strcpy: StrcpyFn = dl(h, b"strcpy\0");
    let g_strcmp: StrcmpFn = dl(h, b"strcmp\0");
    for &n in &[8usize, 16, 32, 64, 128] {
        let s: Vec<u8> = std::iter::repeat(b'a').take(n).chain(std::iter::once(0)).collect();
        let sc = s.as_ptr() as *const c_char;
        let mut dbuf = vec![0u8; n + 1]; let dp = dbuf.as_mut_ptr() as *mut c_char;
        // strcmp: compare against an equal copy differing at last byte
        let mut s2: Vec<u8> = s.clone(); s2[n-1] = b'b'; let s2c = s2.as_ptr() as *const c_char;
        let (mut fcp, mut gcp, mut fcm, mut gcm) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let lit = 200_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..lit { black_box_ptr2(unsafe { frankenlibc_abi::string_abi::strcpy(dp, sc) }); } fcp.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_ptr2(unsafe { g_strcpy(dp, sc) }); } gcp.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_i32(unsafe { frankenlibc_abi::string_abi::strcmp(sc, s2c) }); } fcm.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_i32(unsafe { g_strcmp(sc, s2c) }); } gcm.push(t.elapsed().as_nanos() as f64 / lit as f64);
        }
        println!("STRCPY n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fcp,0.5), pctl(&gcp,0.5), pctl(&fcp,0.5)/pctl(&gcp,0.5));
        println!("STRCMP n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fcm,0.5), pctl(&gcm,0.5), pctl(&fcm,0.5)/pctl(&gcm,0.5));
        // A/B: deployed two-pass strcpy vs fused single-pass bench hook (same process).
        let mut fus = Vec::new();
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..lit { black_box_usize(unsafe { frankenlibc_abi::string_abi::bench_strcpy_fused(dp.cast(), sc.cast()) }); } fus.push(t.elapsed().as_nanos() as f64 / lit as f64);
        }
        println!("STRCPY_FUSED_AB n={n} twopass={:.2} fused={:.2} fused/twopass={:.3}", pctl(&fcp,0.5), pctl(&fus,0.5), pctl(&fus,0.5)/pctl(&fcp,0.5));
    }

    // Wide family honest probe: wcslen + wcscmp deployed no_mangle vs glibc (dlmopen).
    type WcslenFn = unsafe extern "C" fn(*const i32) -> usize;
    type WcscmpFn = unsafe extern "C" fn(*const i32, *const i32) -> i32;
    let g_wcslen: WcslenFn = dl(h, b"wcslen\0");
    let g_wcscmp: WcscmpFn = dl(h, b"wcscmp\0");
    for &n in &[8usize, 16, 32, 64] {
        let w: Vec<i32> = std::iter::repeat(b'a' as i32).take(n).chain(std::iter::once(0)).collect();
        let wp = w.as_ptr();
        let mut w2: Vec<i32> = w.clone(); w2[n-1] = b'b' as i32; let wp2 = w2.as_ptr();
        let (mut fl_, mut gl_, mut fc, mut gc) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let lit = 200_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..lit { black_box_usize(unsafe { frankenlibc_abi::wchar_abi::wcslen(wp.cast::<u32>()) }); } fl_.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_usize(unsafe { g_wcslen(wp) }); } gl_.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_i32(unsafe { frankenlibc_abi::wchar_abi::wcscmp(wp.cast::<u32>(), wp2.cast::<u32>()) }); } fc.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_i32(unsafe { g_wcscmp(wp, wp2) }); } gc.push(t.elapsed().as_nanos() as f64 / lit as f64);
        }
        println!("WCSLEN n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fl_,0.5), pctl(&gl_,0.5), pctl(&fl_,0.5)/pctl(&gl_,0.5));
        println!("WCSCMP n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fc,0.5), pctl(&gc,0.5), pctl(&fc,0.5)/pctl(&gc,0.5));
    }

    // __errno_location: called by ~every errno-setting/reading libc fn. glibc = 1 mov (%fs);
    // fl uses thread_local! + try_with (lazy-init/destructor check). Pervasive systemic tax if slow.
    type ErrnoLocFn = unsafe extern "C" fn() -> *mut i32;
    let g_errno_loc: ErrnoLocFn = dl(h, b"__errno_location\0");
    {
        let (mut fe, mut ge) = (Vec::new(), Vec::new());
        let lit = 500_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..lit { black_box_ptr(unsafe { frankenlibc_abi::errno_abi::__errno_location() } as *mut libc::c_void); } fe.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_ptr(unsafe { g_errno_loc() } as *mut libc::c_void); } ge.push(t.elapsed().as_nanos() as f64 / lit as f64);
        }
        println!("ERRNO_LOC fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fe,0.5), pctl(&ge,0.5), pctl(&fe,0.5)/pctl(&ge,0.5));
    }

    // lseek: fast syscall wrapper. fl calls decide()+observe() (IoFd) on every call; the syscall
    // cost is identical for fl+glibc (same kernel), so fl/glibc isolates the membrane overhead.
    type LseekFn = unsafe extern "C" fn(i32, i64, i32) -> i64;
    let g_lseek: LseekFn = dl(h, b"lseek\0");
    {
        let devnull = unsafe { libc::open(b"/dev/null\0".as_ptr().cast(), libc::O_RDONLY) };
        if devnull >= 0 {
            let (mut fls, mut gls) = (Vec::new(), Vec::new());
            let lit = 300_000u64;
            for _ in 0..100 {
                let t = Instant::now(); for _ in 0..lit { black_box_i64(unsafe { frankenlibc_abi::unistd_abi::lseek(devnull, 0, libc::SEEK_SET) }); } fls.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now(); for _ in 0..lit { black_box_i64(unsafe { g_lseek(devnull, 0, libc::SEEK_SET) }); } gls.push(t.elapsed().as_nanos() as f64 / lit as f64);
            }
            println!("LSEEK fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fls,0.5), pctl(&gls,0.5), pctl(&fls,0.5)/pctl(&gls,0.5));
            unsafe { libc::close(devnull); }
        }
    }

    // rand + random: PRNG (mutates global state -> no const-fold). glibc random() = expensive
    // nonlinear additive-feedback generator; a simpler fl PRNG could win. dlmopen glibc.
    type RandFn = unsafe extern "C" fn() -> i32;
    type RandomFn = unsafe extern "C" fn() -> libc::c_long;
    let g_rand: RandFn = dl(h, b"rand\0");
    let g_random: RandomFn = dl(h, b"random\0");
    {
        let (mut fr, mut gr, mut frnd, mut grnd) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let lit = 500_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..lit { black_box_i32(unsafe { frankenlibc_abi::stdlib_abi::rand() }); } fr.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_i32(unsafe { g_rand() }); } gr.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_i64(unsafe { frankenlibc_abi::stdlib_abi::random() as i64 }); } frnd.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_i64(unsafe { g_random() as i64 }); } grnd.push(t.elapsed().as_nanos() as f64 / lit as f64);
        }
        println!("RAND fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fr,0.5), pctl(&gr,0.5), pctl(&fr,0.5)/pctl(&gr,0.5));
        println!("RANDOM fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&frnd,0.5), pctl(&grnd,0.5), pctl(&frnd,0.5)/pctl(&grnd,0.5));
    }

    // strcat: builder = scan dst-to-NUL + copy src. Common; can hide two-pass/naive issues.
    type StrcatFn = unsafe extern "C" fn(*mut c_char, *const c_char) -> *mut c_char;
    let g_strcat: StrcatFn = dl(h, b"strcat\0");
    for &(dn, sn) in &[(8usize, 8usize), (32, 16), (64, 32)] {
        let src: Vec<u8> = std::iter::repeat(b'b').take(sn).chain(std::iter::once(0)).collect();
        let scp = src.as_ptr() as *const c_char;
        // dst buffer: dn-char prefix + NUL, big enough for prefix+src+NUL; reset NUL each call.
        let mut dbuf = vec![0u8; dn + sn + 8];
        for i in 0..dn { dbuf[i] = b'a'; }
        let dp = dbuf.as_mut_ptr() as *mut c_char;
        let (mut fc, mut gc) = (Vec::new(), Vec::new());
        let lit = 200_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..lit { unsafe { dbuf[dn] = 0; black_box_ptr2(frankenlibc_abi::string_abi::strcat(dp, scp)); } } fc.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { unsafe { dbuf[dn] = 0; black_box_ptr2(g_strcat(dp, scp)); } } gc.push(t.elapsed().as_nanos() as f64 / lit as f64);
        }
        println!("STRCAT dn={dn} sn={sn} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fc,0.5), pctl(&gc,0.5), pctl(&fc,0.5)/pctl(&gc,0.5));
    }

    // memmem + strspn: honest dlmopen certification of claimed algorithmic wins (Two-Way / bitmap).
    type MemmemFn = unsafe extern "C" fn(*const libc::c_void, usize, *const libc::c_void, usize) -> *mut libc::c_void;
    type StrspnFn = unsafe extern "C" fn(*const c_char, *const c_char) -> usize;
    let g_memmem: MemmemFn = dl(h, b"memmem\0");
    let g_strspn: StrspnFn = dl(h, b"strspn\0");
    {
        // pathological: haystack "aaa...a" (4096), needle "aa..ac" (32) — forces naive quadratic.
        let hay: Vec<u8> = std::iter::repeat(b'a').take(4096).collect();
        let mut ndl: Vec<u8> = std::iter::repeat(b'a').take(32).collect(); ndl[31] = b'c';
        let (hp, hl, np, nl) = (hay.as_ptr() as *const libc::c_void, hay.len(), ndl.as_ptr() as *const libc::c_void, ndl.len());
        let (mut fm, mut gm) = (Vec::new(), Vec::new());
        let lit = 20_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..lit { black_box_ptr3(unsafe { frankenlibc_abi::string_abi::memmem(hp, hl, np, nl) }); } fm.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_ptr3(unsafe { g_memmem(hp, hl, np, nl) }); } gm.push(t.elapsed().as_nanos() as f64 / lit as f64);
        }
        println!("MEMMEM_PATHO fl={:.1} glibc={:.1} fl/glibc={:.3}", pctl(&fm,0.5), pctl(&gm,0.5), pctl(&fm,0.5)/pctl(&gm,0.5));
    }
    {
        // strspn: span of a 64-char string over a 4-char accept set (bitmap vs glibc).
        let s = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX\0";
        let acc = b"abcd\0";
        let (sp, ap) = (s.as_ptr() as *const c_char, acc.as_ptr() as *const c_char);
        let (mut fs2, mut gs2) = (Vec::new(), Vec::new());
        let lit = 200_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..lit { black_box_usize(unsafe { frankenlibc_abi::string_abi::strspn(sp, ap) }); } fs2.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_usize(unsafe { g_strspn(sp, ap) }); } gs2.push(t.elapsed().as_nanos() as f64 / lit as f64);
        }
        println!("STRSPN fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fs2,0.5), pctl(&gs2,0.5), pctl(&fs2,0.5)/pctl(&gs2,0.5));
    }

    // malloc+free: fl strict malloc DELEGATES to native glibc malloc + membrane overhead
    // (entrypoint_scope + reentry_guard + decide + fallback_insert_sized + record_stats + observe),
    // so fl = glibc + pure removable tax. vs glibc dlmopen. THE biggest documented gap (~50x).
    type MallocFn = unsafe extern "C" fn(usize) -> *mut libc::c_void;
    type FreeFn = unsafe extern "C" fn(*mut libc::c_void);
    let g_malloc: MallocFn = dl(h, b"malloc\0");
    let g_free: FreeFn = dl(h, b"free\0");
    for &sz in &[16usize, 64, 256] {
        // warm
        for _ in 0..1000 { unsafe { let p = frankenlibc_abi::malloc_abi::malloc(sz); frankenlibc_abi::malloc_abi::free(p); let q = g_malloc(sz); g_free(q); } }
        let (mut flv, mut glv) = (Vec::new(), Vec::new());
        let lit = 100_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..lit { unsafe { let p = frankenlibc_abi::malloc_abi::malloc(sz); std::hint::black_box(p); frankenlibc_abi::malloc_abi::free(p); } } flv.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { unsafe { let p = g_malloc(sz); std::hint::black_box(p); g_free(p); } } glv.push(t.elapsed().as_nanos() as f64 / lit as f64);
        }
        println!("MALLOC_FREE sz={sz} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&flv,0.5), pctl(&glv,0.5), pctl(&flv,0.5)/pctl(&glv,0.5));
    }

    // mktime: ApiFamily::Time is MISSING from the decide/observe fast-path list, so it pays
    // the full membrane tax per call (kernel evidence consult + telemetry). vs glibc dlmopen.
    type MktimeFn = unsafe extern "C" fn(*mut libc::tm) -> i64;
    let g_mktime: MktimeFn = dl(h, b"mktime\0");
    {
        let mk = || { let mut t: libc::tm = unsafe { std::mem::zeroed() };
            t.tm_year = 125; t.tm_mon = 6; t.tm_mday = 2; t.tm_hour = 12; t.tm_min = 30; t.tm_sec = 0; t };
        // normalize once (both idempotent after)
        let mut ft = mk(); let mut gt = mk();
        unsafe { frankenlibc_abi::time_abi::mktime(&mut ft); g_mktime(&mut gt); }
        let (mut flv, mut glv) = (Vec::new(), Vec::new());
        let lit = 200_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..lit { black_box_i64(unsafe { frankenlibc_abi::time_abi::mktime(&mut ft) }); } flv.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_i64(unsafe { g_mktime(&mut gt) }); } glv.push(t.elapsed().as_nanos() as f64 / lit as f64);
        }
        println!("MKTIME fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&flv,0.5), pctl(&glv,0.5), pctl(&flv,0.5)/pctl(&glv,0.5));
    }
    { // atoi/strtol: hot pure-computation integer parse (Stdlib family), vs glibc dlmopen
        type AtoiFn = unsafe extern "C" fn(*const c_char) -> i32;
        type StrtolFn = unsafe extern "C" fn(*const c_char, *mut *mut c_char, i32) -> i64;
        let g_atoi: AtoiFn = dl(h, b"atoi\0");
        let g_strtol: StrtolFn = dl(h, b"strtol\0");
        let s = b"-1234567\0"; let sp = s.as_ptr() as *const c_char;
        let (mut fa, mut ga, mut fs2, mut gs2) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let lit = 200_000u64;
        for _ in 0..100 {
            let t = Instant::now(); for _ in 0..lit { black_box_i32(unsafe { frankenlibc_abi::stdlib_abi::atoi(sp) }); } fa.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_i32(unsafe { g_atoi(sp) }); } ga.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_i64(unsafe { frankenlibc_abi::stdlib_abi::strtol(sp, std::ptr::null_mut(), 10) }); } fs2.push(t.elapsed().as_nanos() as f64 / lit as f64);
            let t = Instant::now(); for _ in 0..lit { black_box_i64(unsafe { g_strtol(sp, std::ptr::null_mut(), 10) }); } gs2.push(t.elapsed().as_nanos() as f64 / lit as f64);
        }
        println!("ATOI fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fa,0.5), pctl(&ga,0.5), pctl(&fa,0.5)/pctl(&ga,0.5));
        println!("STRTOL fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fs2,0.5), pctl(&gs2,0.5), pctl(&fs2,0.5)/pctl(&gs2,0.5));
    }
}

#[inline(never)]
fn black_box_ptr2(v: *mut c_char) -> *mut c_char { std::hint::black_box(v) }

#[inline(never)]
fn black_box_i64(v: i64) -> i64 { std::hint::black_box(v) }

#[inline(never)]
fn black_box_i32(v: i32) -> i32 { std::hint::black_box(v) }

#[inline(never)]
fn black_box_bool(v: bool) -> bool { std::hint::black_box(v) }

#[inline(never)]
fn black_box_usize(v: usize) -> usize { std::hint::black_box(v) }
#[inline(never)]
fn black_box_ptr(v: *mut libc::c_void) -> *mut libc::c_void { std::hint::black_box(v) }

#[inline(never)]
fn black_box_ptr3(v: *mut libc::c_void) -> *mut libc::c_void { std::hint::black_box(v) }
