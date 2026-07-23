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
}
