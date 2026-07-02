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
}

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
