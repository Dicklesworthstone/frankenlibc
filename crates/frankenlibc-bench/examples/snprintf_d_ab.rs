//! snprintf `%d` A/B: deployed fl vs host glibc (dlmopen). Measures the strict `%d` fast path
//! (cc-snprintf-d-2026-07-23) that gives signed-decimal the same membrane bypass `%u`/`%c`/`%p`
//! already had. `%u` is measured alongside as the already-fast reference. Byte-identity is
//! asserted over 0 / +ve / -ve / i32::MIN / i32::MAX before any timing.
//!
//! Run: `cargo run --release -p frankenlibc-bench --features abi-bench --example snprintf_d_ab`

use std::ffi::{c_char, c_int, c_uint, c_void};
use std::hint::black_box;
use std::time::Instant;

type SnD = unsafe extern "C" fn(*mut c_char, usize, *const c_char, c_int) -> c_int;
type SnU = unsafe extern "C" fn(*mut c_char, usize, *const c_char, c_uint) -> c_int;

fn glibc_handle() -> *mut c_void {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen failed");
        h
    }
}

fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

fn cv(v: &[f64]) -> f64 {
    let m = v.iter().sum::<f64>() / v.len() as f64;
    if m == 0.0 {
        return 0.0;
    }
    let var = v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / v.len() as f64;
    100.0 * var.sqrt() / m
}

fn main() {
    let fl_d: SnD = unsafe {
        std::mem::transmute::<*const (), SnD>(frankenlibc_abi::stdio_abi::snprintf as *const ())
    };
    let fl_u: SnU = unsafe {
        std::mem::transmute::<*const (), SnU>(frankenlibc_abi::stdio_abi::snprintf as *const ())
    };
    let h = glibc_handle();
    let g = unsafe { libc::dlsym(h, c"snprintf".as_ptr()) };
    assert!(!g.is_null(), "dlsym snprintf failed");
    let g_d: SnD = unsafe { std::mem::transmute::<*mut c_void, SnD>(g) };
    let g_u: SnU = unsafe { std::mem::transmute::<*mut c_void, SnU>(g) };

    let fmt_d = c"%d";
    let fmt_u = c"%u";

    // Byte-identity: fl == glibc across the full signed-int edge set.
    for &n in &[0i32, 1, -1, 42, -42, 12345, -12345, i32::MIN, i32::MAX, 100000, -999999] {
        let mut fb = [0u8; 32];
        let mut gb = [0u8; 32];
        let fr = unsafe { fl_d(fb.as_mut_ptr().cast(), 32, fmt_d.as_ptr(), n) };
        let gr = unsafe { g_d(gb.as_mut_ptr().cast(), 32, fmt_d.as_ptr(), n) };
        assert_eq!(fr, gr, "snprintf %d return diverged for {n}");
        assert_eq!(fb, gb, "snprintf %d bytes diverged for {n}");
    }
    // Truncation contract: size=4 on -12345 must write "-12" + NUL and return 6.
    {
        let mut fb = [0x5au8; 8];
        let mut gb = [0x5au8; 8];
        let fr = unsafe { fl_d(fb.as_mut_ptr().cast(), 4, fmt_d.as_ptr(), -12345) };
        let gr = unsafe { g_d(gb.as_mut_ptr().cast(), 4, fmt_d.as_ptr(), -12345) };
        assert_eq!(fr, gr, "snprintf %d trunc return diverged");
        assert_eq!(fb, gb, "snprintf %d trunc bytes diverged");
    }
    println!("verify: OK (fl snprintf %d == glibc, values + truncation)");

    let iters = 50_000u64;
    let mut buf = [0u8; 32];
    // Collect per-arm samples for median+cv.
    let collect = |f: &dyn Fn()| -> (f64, f64) {
        for _ in 0..5 {
            f();
        }
        let mut s = Vec::with_capacity(60);
        for _ in 0..60 {
            let t = Instant::now();
            for _ in 0..iters {
                f();
            }
            s.push(t.elapsed().as_nanos() as f64 / iters as f64);
        }
        (pctl(&s, 0.5), cv(&s))
    };

    let bp = buf.as_mut_ptr();
    let (fld, fld_cv) = collect(&|| {
        black_box(unsafe { fl_d(black_box(bp).cast(), 32, fmt_d.as_ptr(), black_box(-12345)) });
    });
    let (gld, gld_cv) = collect(&|| {
        black_box(unsafe { g_d(black_box(bp).cast(), 32, fmt_d.as_ptr(), black_box(-12345)) });
    });
    let (flu, flu_cv) = collect(&|| {
        black_box(unsafe { fl_u(black_box(bp).cast(), 32, fmt_u.as_ptr(), black_box(12345u32)) });
    });
    let (glu, glu_cv) = collect(&|| {
        black_box(unsafe { g_u(black_box(bp).cast(), 32, fmt_u.as_ptr(), black_box(12345u32)) });
    });

    println!(
        "SNPRINTF_D fl={fld:.2}ns cv={fld_cv:.2} glibc={gld:.2}ns cv={gld_cv:.2} fl/glibc={:.3}",
        fld / gld
    );
    println!(
        "SNPRINTF_U fl={flu:.2}ns cv={flu_cv:.2} glibc={glu:.2}ns cv={glu_cv:.2} fl/glibc={:.3} (already-fast reference)",
        flu / glu
    );

    // sprintf %d/%u (unbounded). glibc sprintf via the same dlmopen handle.
    type SpD = unsafe extern "C" fn(*mut c_char, *const c_char, c_int) -> c_int;
    type SpU = unsafe extern "C" fn(*mut c_char, *const c_char, c_uint) -> c_int;
    let fl_sp_d: SpD = unsafe {
        std::mem::transmute::<*const (), SpD>(frankenlibc_abi::stdio_abi::sprintf as *const ())
    };
    let fl_sp_u: SpU = unsafe {
        std::mem::transmute::<*const (), SpU>(frankenlibc_abi::stdio_abi::sprintf as *const ())
    };
    let gsp = unsafe { libc::dlsym(h, c"sprintf".as_ptr()) };
    assert!(!gsp.is_null());
    let g_sp_d: SpD = unsafe { std::mem::transmute::<*mut c_void, SpD>(gsp) };
    // sprintf byte-identity over the signed edge set.
    for &n in &[0i32, -1, 12345, -12345, i32::MIN, i32::MAX] {
        let mut fb = [0u8; 32];
        let mut gb = [0u8; 32];
        let fr = unsafe { fl_sp_d(fb.as_mut_ptr().cast(), fmt_d.as_ptr(), n) };
        let gr = unsafe { g_sp_d(gb.as_mut_ptr().cast(), fmt_d.as_ptr(), n) };
        assert_eq!(fr, gr, "sprintf %d return diverged for {n}");
        assert_eq!(fb, gb, "sprintf %d bytes diverged for {n}");
    }
    println!("verify: OK (fl sprintf %d == glibc)");
    let (spd, spd_cv) = collect(&|| {
        black_box(unsafe { fl_sp_d(black_box(bp).cast(), fmt_d.as_ptr(), black_box(-12345)) });
    });
    let (spu, spu_cv) = collect(&|| {
        black_box(unsafe { fl_sp_u(black_box(bp).cast(), fmt_u.as_ptr(), black_box(12345u32)) });
    });
    let (gspd, gspd_cv) = collect(&|| {
        black_box(unsafe { g_sp_d(black_box(bp).cast(), fmt_d.as_ptr(), black_box(-12345)) });
    });
    println!(
        "SPRINTF_D fl={spd:.2}ns cv={spd_cv:.2} glibc={gspd:.2}ns cv={gspd_cv:.2} fl/glibc={:.3}",
        spd / gspd
    );
    println!("SPRINTF_U fl={spu:.2}ns cv={spu_cv:.2} (fl-only, was also missing)");

    // %x (unsigned hex) — snprintf + sprintf. Byte-identity over the hex edge set.
    let fmt_x = c"%x";
    for &n in &[0u32, 1, 0xff, 0xdead_beef, u32::MAX, 0x1234_5678] {
        let mut fb = [0u8; 32];
        let mut gb = [0u8; 32];
        let fr = unsafe { fl_u(fb.as_mut_ptr().cast(), 32, fmt_x.as_ptr(), n) };
        let gr = unsafe { g_u(gb.as_mut_ptr().cast(), 32, fmt_x.as_ptr(), n) };
        assert_eq!(fr, gr, "snprintf %x return diverged for {n:#x}");
        assert_eq!(fb, gb, "snprintf %x bytes diverged for {n:#x}");
        let mut fb2 = [0u8; 32];
        let mut gb2 = [0u8; 32];
        let fr2 = unsafe { fl_sp_u(fb2.as_mut_ptr().cast(), fmt_x.as_ptr(), n) };
        let gr2 = unsafe { g_sp_d(gb2.as_mut_ptr().cast(), fmt_x.as_ptr(), n as c_int) };
        assert_eq!(fr2, gr2, "sprintf %x return diverged for {n:#x}");
        assert_eq!(fb2, gb2, "sprintf %x bytes diverged for {n:#x}");
    }
    println!("verify: OK (fl snprintf/sprintf %x == glibc)");
    let (snx, snx_cv) = collect(&|| {
        black_box(unsafe { fl_u(black_box(bp).cast(), 32, fmt_x.as_ptr(), black_box(0xdead_beefu32)) });
    });
    let (gsnx, gsnx_cv) = collect(&|| {
        black_box(unsafe { g_u(black_box(bp).cast(), 32, fmt_x.as_ptr(), black_box(0xdead_beefu32)) });
    });
    let (spx, spx_cv) = collect(&|| {
        black_box(unsafe { fl_sp_u(black_box(bp).cast(), fmt_x.as_ptr(), black_box(0xdead_beefu32)) });
    });
    println!(
        "SNPRINTF_X fl={snx:.2}ns cv={snx_cv:.2} glibc={gsnx:.2}ns cv={gsnx_cv:.2} fl/glibc={:.3}",
        snx / gsnx
    );
    println!("SPRINTF_X fl={spx:.2}ns cv={spx_cv:.2} (fl-only)");

    // %ld (64-bit signed long) — snprintf. Byte-identity over the i64 edge set.
    type SnLd = unsafe extern "C" fn(*mut c_char, usize, *const c_char, i64) -> c_int;
    let fmt_ld = c"%ld";
    let fl_ld: SnLd = unsafe {
        std::mem::transmute::<*const (), SnLd>(frankenlibc_abi::stdio_abi::snprintf as *const ())
    };
    let g_ld: SnLd = unsafe { std::mem::transmute::<*mut c_void, SnLd>(g) };
    for &n in &[0i64, -1, 12345, -12345, i64::MIN, i64::MAX, 9_000_000_000, -9_000_000_000] {
        let mut fb = [0u8; 32];
        let mut gb = [0u8; 32];
        let fr = unsafe { fl_ld(fb.as_mut_ptr().cast(), 32, fmt_ld.as_ptr(), n) };
        let gr = unsafe { g_ld(gb.as_mut_ptr().cast(), 32, fmt_ld.as_ptr(), n) };
        assert_eq!(fr, gr, "snprintf %ld return diverged for {n}");
        assert_eq!(fb, gb, "snprintf %ld bytes diverged for {n}");
    }
    println!("verify: OK (fl snprintf %ld == glibc)");
    let (snld, snld_cv) = collect(&|| {
        black_box(unsafe { fl_ld(black_box(bp).cast(), 32, fmt_ld.as_ptr(), black_box(-9_000_000_000i64)) });
    });
    let (gsnld, gsnld_cv) = collect(&|| {
        black_box(unsafe { g_ld(black_box(bp).cast(), 32, fmt_ld.as_ptr(), black_box(-9_000_000_000i64)) });
    });
    println!(
        "SNPRINTF_LD fl={snld:.2}ns cv={snld_cv:.2} glibc={gsnld:.2}ns cv={gsnld_cv:.2} fl/glibc={:.3}",
        snld / gsnld
    );

    // %zu (size_t) — reuses the %lu helper. Byte-identity over the usize edge set.
    type SnZu = unsafe extern "C" fn(*mut c_char, usize, *const c_char, usize) -> c_int;
    let fmt_zu = c"%zu";
    let fl_zu: SnZu = unsafe {
        std::mem::transmute::<*const (), SnZu>(frankenlibc_abi::stdio_abi::snprintf as *const ())
    };
    let g_zu: SnZu = unsafe { std::mem::transmute::<*mut c_void, SnZu>(g) };
    for &n in &[0usize, 1, 12345, usize::MAX, 9_000_000_000, 4096] {
        let mut fb = [0u8; 32];
        let mut gb = [0u8; 32];
        let fr = unsafe { fl_zu(fb.as_mut_ptr().cast(), 32, fmt_zu.as_ptr(), n) };
        let gr = unsafe { g_zu(gb.as_mut_ptr().cast(), 32, fmt_zu.as_ptr(), n) };
        assert_eq!(fr, gr, "snprintf %zu return diverged for {n}");
        assert_eq!(fb, gb, "snprintf %zu bytes diverged for {n}");
    }
    println!("verify: OK (fl snprintf %zu == glibc)");
    let (snzu, snzu_cv) = collect(&|| {
        black_box(unsafe { fl_zu(black_box(bp).cast(), 32, fmt_zu.as_ptr(), black_box(9_000_000_000usize)) });
    });
    let (gsnzu, gsnzu_cv) = collect(&|| {
        black_box(unsafe { g_zu(black_box(bp).cast(), 32, fmt_zu.as_ptr(), black_box(9_000_000_000usize)) });
    });
    println!(
        "SNPRINTF_ZU fl={snzu:.2}ns cv={snzu_cv:.2} glibc={gsnzu:.2}ns cv={gsnzu_cv:.2} fl/glibc={:.3}",
        snzu / gsnzu
    );

    // %lx (64-bit lowercase hex) — reuses SnZu signature shape (usize arg == u64). Byte-identity.
    let fmt_lx = c"%lx";
    for &n in &[0usize, 1, 0xff, 0xdead_beef, 0xdead_beef_cafe_babe, usize::MAX, 4096] {
        let mut fb = [0u8; 32];
        let mut gb = [0u8; 32];
        let fr = unsafe { fl_zu(fb.as_mut_ptr().cast(), 32, fmt_lx.as_ptr(), n) };
        let gr = unsafe { g_zu(gb.as_mut_ptr().cast(), 32, fmt_lx.as_ptr(), n) };
        assert_eq!(fr, gr, "snprintf %lx return diverged for {n:#x}");
        assert_eq!(fb, gb, "snprintf %lx bytes diverged for {n:#x}");
    }
    println!("verify: OK (fl snprintf %lx == glibc)");
    let (snlx, snlx_cv) = collect(&|| {
        black_box(unsafe { fl_zu(black_box(bp).cast(), 32, fmt_lx.as_ptr(), black_box(0xdead_beef_cafe_babeusize)) });
    });
    let (gsnlx, gsnlx_cv) = collect(&|| {
        black_box(unsafe { g_zu(black_box(bp).cast(), 32, fmt_lx.as_ptr(), black_box(0xdead_beef_cafe_babeusize)) });
    });
    println!(
        "SNPRINTF_LX fl={snlx:.2}ns cv={snlx_cv:.2} glibc={gsnlx:.2}ns cv={gsnlx_cv:.2} fl/glibc={:.3}",
        snlx / gsnlx
    );

    // PROFILE-FIRST: fprintf("%d\n") to a Full-buffered /dev/null stream. Measures the printf/
    // fprintf full-render gap (they have no integer fast path). fl vs glibc, each its own stream.
    type FopenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
    type FprintfD = unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int;
    let fl_fopen: FopenFn = unsafe {
        std::mem::transmute::<*const (), FopenFn>(frankenlibc_abi::stdio_abi::fopen as *const ())
    };
    let fl_fprintf: FprintfD = unsafe {
        std::mem::transmute::<*const (), FprintfD>(frankenlibc_abi::stdio_abi::fprintf as *const ())
    };
    let g_fopen: FopenFn = unsafe { std::mem::transmute::<*mut c_void, FopenFn>(libc::dlsym(h, c"fopen".as_ptr())) };
    let g_fprintf: FprintfD = unsafe { std::mem::transmute::<*mut c_void, FprintfD>(libc::dlsym(h, c"fprintf".as_ptr())) };
    // Byte-identity: fl fprintf vs glibc fprintf into fmemopen "w" buffers, over the edge set +
    // both "%d" and "%d\n". Proves the stream fast path emits the exact bytes.
    type FmemFn = unsafe extern "C" fn(*mut c_void, usize, *const c_char) -> *mut c_void;
    type FcloseFn2 = unsafe extern "C" fn(*mut c_void) -> c_int;
    let fl_fmem: FmemFn = unsafe {
        std::mem::transmute::<*const (), FmemFn>(frankenlibc_abi::stdio_abi::fmemopen as *const ())
    };
    let g_fmem: FmemFn = unsafe { std::mem::transmute::<*mut c_void, FmemFn>(libc::dlsym(h, c"fmemopen".as_ptr())) };
    let fl_fclose2: FcloseFn2 = unsafe {
        std::mem::transmute::<*const (), FcloseFn2>(frankenlibc_abi::stdio_abi::fclose as *const ())
    };
    let g_fclose2: FcloseFn2 = unsafe { std::mem::transmute::<*mut c_void, FcloseFn2>(libc::dlsym(h, c"fclose".as_ptr())) };
    for &nl in &[c"%d".as_ptr(), c"%d\n".as_ptr()] {
        for &n in &[0i32, -1, 12345, -12345, i32::MIN, i32::MAX] {
            let mut flbuf = [0u8; 32];
            let mut gbuf = [0u8; 32];
            let fmp = unsafe { fl_fmem(flbuf.as_mut_ptr().cast(), 32, c"w".as_ptr()) };
            let gmp = unsafe { g_fmem(gbuf.as_mut_ptr().cast(), 32, c"w".as_ptr()) };
            let fr = unsafe { fl_fprintf(fmp, nl, n) };
            let gr = unsafe { g_fprintf(gmp, nl, n) };
            unsafe { fl_fclose2(fmp) };
            unsafe { g_fclose2(gmp) };
            assert_eq!(fr, gr, "fprintf return diverged for {n}");
            assert_eq!(flbuf, gbuf, "fprintf bytes diverged for {n}");
        }
    }
    println!("verify: OK (fl fprintf %d/%d\\n == glibc, values + bytes)");
    // fprintf %u/%x byte-identity (unsigned).
    type FprintfU = unsafe extern "C" fn(*mut c_void, *const c_char, c_uint) -> c_int;
    let fl_fprintf_u: FprintfU = unsafe { std::mem::transmute::<*const (), FprintfU>(frankenlibc_abi::stdio_abi::fprintf as *const ()) };
    let g_fprintf_u: FprintfU = unsafe { std::mem::transmute::<*mut c_void, FprintfU>(libc::dlsym(h, c"fprintf".as_ptr())) };
    for &uf in &[c"%u".as_ptr(), c"%u\n".as_ptr(), c"%x".as_ptr(), c"%x\n".as_ptr()] {
        for &n in &[0u32, 1, 0xff, 0xdead_beef, u32::MAX, 12345] {
            let mut flbuf = [0u8; 32];
            let mut gbuf = [0u8; 32];
            let fmp = unsafe { fl_fmem(flbuf.as_mut_ptr().cast(), 32, c"w".as_ptr()) };
            let gmp = unsafe { g_fmem(gbuf.as_mut_ptr().cast(), 32, c"w".as_ptr()) };
            let fr = unsafe { fl_fprintf_u(fmp, uf, n) };
            let gr = unsafe { g_fprintf_u(gmp, uf, n) };
            unsafe { fl_fclose2(fmp) };
            unsafe { g_fclose2(gmp) };
            assert_eq!(fr, gr, "fprintf %u/%x return diverged for {n:#x}");
            assert_eq!(flbuf, gbuf, "fprintf %u/%x bytes diverged for {n:#x}");
        }
    }
    println!("verify: OK (fl fprintf %u/%x == glibc)");
    // fprintf 64-bit %ld/%lu/%lx byte-identity.
    type FprintfL = unsafe extern "C" fn(*mut c_void, *const c_char, u64) -> c_int;
    let fl_fprintf_l: FprintfL = unsafe { std::mem::transmute::<*const (), FprintfL>(frankenlibc_abi::stdio_abi::fprintf as *const ()) };
    let g_fprintf_l: FprintfL = unsafe { std::mem::transmute::<*mut c_void, FprintfL>(libc::dlsym(h, c"fprintf".as_ptr())) };
    let lfmts: [(&core::ffi::CStr, u64); 6] = [
        (c"%ld", (-9_000_000_000i64) as u64), (c"%ld\n", i64::MIN as u64),
        (c"%lu", u64::MAX), (c"%lu\n", 9_000_000_000u64),
        (c"%lx", 0xdead_beef_cafe_babeu64), (c"%lx\n", u64::MAX),
    ];
    for &(lf, n) in &lfmts {
        let mut flbuf = [0u8; 40];
        let mut gbuf = [0u8; 40];
        let fmp = unsafe { fl_fmem(flbuf.as_mut_ptr().cast(), 40, c"w".as_ptr()) };
        let gmp = unsafe { g_fmem(gbuf.as_mut_ptr().cast(), 40, c"w".as_ptr()) };
        let fr = unsafe { fl_fprintf_l(fmp, lf.as_ptr(), n) };
        let gr = unsafe { g_fprintf_l(gmp, lf.as_ptr(), n) };
        unsafe { fl_fclose2(fmp) };
        unsafe { g_fclose2(gmp) };
        assert_eq!(fr, gr, "fprintf 64-bit return diverged for {n:#x}");
        assert_eq!(flbuf, gbuf, "fprintf 64-bit bytes diverged for {n:#x}");
    }
    println!("verify: OK (fl fprintf %ld/%lu/%lx == glibc)");

    let fl_fp = unsafe { fl_fopen(c"/dev/null".as_ptr(), c"w".as_ptr()) };
    let g_fp = unsafe { g_fopen(c"/dev/null".as_ptr(), c"w".as_ptr()) };
    assert!(!fl_fp.is_null() && !g_fp.is_null(), "fopen /dev/null failed");
    let fmt_dn = c"%d\n";
    let (fprd, fprd_cv) = collect(&|| {
        black_box(unsafe { fl_fprintf(fl_fp, fmt_dn.as_ptr(), black_box(-12345)) });
    });
    let (gfprd, gfprd_cv) = collect(&|| {
        black_box(unsafe { g_fprintf(g_fp, fmt_dn.as_ptr(), black_box(-12345)) });
    });
    println!(
        "FPRINTF_DN fl={fprd:.2}ns cv={fprd_cv:.2} glibc={gfprd:.2}ns cv={gfprd_cv:.2} fl/glibc={:.3}",
        fprd / gfprd
    );
    let fmt_xn = c"%x\n";
    let (fprx, fprx_cv) = collect(&|| {
        black_box(unsafe { fl_fprintf_u(fl_fp, fmt_xn.as_ptr(), black_box(0xdead_beefu32)) });
    });
    let (gfprx, gfprx_cv) = collect(&|| {
        black_box(unsafe { g_fprintf_u(g_fp, fmt_xn.as_ptr(), black_box(0xdead_beefu32)) });
    });
    println!(
        "FPRINTF_XN fl={fprx:.2}ns cv={fprx_cv:.2} glibc={gfprx:.2}ns cv={gfprx_cv:.2} fl/glibc={:.3}",
        fprx / gfprx
    );
    let fmt_ldn = c"%ld\n";
    let (fprl, fprl_cv) = collect(&|| {
        black_box(unsafe { fl_fprintf_l(fl_fp, fmt_ldn.as_ptr(), black_box((-9_000_000_000i64) as u64)) });
    });
    let (gfprl, gfprl_cv) = collect(&|| {
        black_box(unsafe { g_fprintf_l(g_fp, fmt_ldn.as_ptr(), black_box((-9_000_000_000i64) as u64)) });
    });
    println!(
        "FPRINTF_LDN fl={fprl:.2}ns cv={fprl_cv:.2} glibc={gfprl:.2}ns cv={gfprl_cv:.2} fl/glibc={:.3}",
        fprl / gfprl
    );
}
