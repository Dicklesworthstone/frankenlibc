//! In-process A/B for `__wcsftime_l`: old heap transcode vs delegated wcsftime.

use std::ffi::{c_char, c_void};
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_abi::{time_abi, wchar_abi};

type WcsftimeLFn = unsafe extern "C" fn(
    *mut libc::wchar_t,
    usize,
    *const libc::wchar_t,
    *const libc::tm,
    *mut c_void,
) -> usize;

type NewLocaleFn = unsafe extern "C" fn(i32, *const c_char, *mut c_void) -> *mut c_void;

fn percentile(samples: &[f64], q: f64) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((q * (sorted.len() - 1) as f64).round() as usize).min(sorted.len() - 1);
    sorted[idx]
}

fn bench3<A, B, C>(mut a: A, mut b: B, mut c: C) -> (f64, f64, f64)
where
    A: FnMut(),
    B: FnMut(),
    C: FnMut(),
{
    let mut aa = Vec::new();
    let mut bb = Vec::new();
    let mut cc = Vec::new();
    for round in 0..48 {
        match round % 3 {
            0 => {
                let t = Instant::now();
                a();
                aa.push(t.elapsed().as_nanos() as f64);
                let t = Instant::now();
                b();
                bb.push(t.elapsed().as_nanos() as f64);
                let t = Instant::now();
                c();
                cc.push(t.elapsed().as_nanos() as f64);
            }
            1 => {
                let t = Instant::now();
                b();
                bb.push(t.elapsed().as_nanos() as f64);
                let t = Instant::now();
                c();
                cc.push(t.elapsed().as_nanos() as f64);
                let t = Instant::now();
                a();
                aa.push(t.elapsed().as_nanos() as f64);
            }
            _ => {
                let t = Instant::now();
                c();
                cc.push(t.elapsed().as_nanos() as f64);
                let t = Instant::now();
                a();
                aa.push(t.elapsed().as_nanos() as f64);
                let t = Instant::now();
                b();
                bb.push(t.elapsed().as_nanos() as f64);
            }
        }
    }
    (
        percentile(&aa, 0.10),
        percentile(&bb, 0.10),
        percentile(&cc, 0.10),
    )
}

fn wide_cstr(s: &str) -> Vec<libc::wchar_t> {
    s.chars()
        .map(|ch| ch as libc::wchar_t)
        .chain(std::iter::once(0))
        .collect()
}

unsafe fn old_wcsftime_l(
    s: *mut libc::wchar_t,
    max: usize,
    format: *const libc::wchar_t,
    tm: *const c_void,
) -> usize {
    if s.is_null() || format.is_null() || tm.is_null() || max == 0 {
        return 0;
    }

    let mut fmt_narrow = Vec::new();
    let mut fmt = format;
    loop {
        // SAFETY: benchmark inputs are valid NUL-terminated wide C strings.
        let wc = unsafe { *fmt };
        fmt_narrow.push(wc as u8);
        if wc == 0 {
            break;
        }
        // SAFETY: still within the benchmark's NUL-terminated format.
        fmt = unsafe { fmt.add(1) };
    }

    let mut buf = vec![0u8; max * 4];
    let ret = unsafe {
        time_abi::strftime(
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            fmt_narrow.as_ptr() as *const c_char,
            tm as *const libc::tm,
        )
    };
    if ret == 0 {
        return 0;
    }

    let mut i = 0usize;
    for &byte in &buf[..ret] {
        if i >= max - 1 {
            break;
        }
        // SAFETY: `i < max - 1`, so the char and terminator fit.
        unsafe { *s.add(i) = byte as libc::wchar_t };
        i += 1;
    }
    // SAFETY: see loop safety above.
    unsafe { *s.add(i) = 0 };
    i
}

fn tag(ratio: f64) -> &'static str {
    if ratio < 0.90 {
        "WIN"
    } else if ratio > 1.10 {
        "LOSS"
    } else {
        "PAR"
    }
}

fn main() {
    let libc_handle = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!libc_handle.is_null());

    let setlocale_sym = unsafe { libc::dlsym(libc_handle, c"setlocale".as_ptr()) };
    let newlocale_sym = unsafe { libc::dlsym(libc_handle, c"newlocale".as_ptr()) };
    let wcsftime_l_sym = unsafe { libc::dlsym(libc_handle, c"wcsftime_l".as_ptr()) };
    let gmtime_r_sym = unsafe { libc::dlsym(libc_handle, c"gmtime_r".as_ptr()) };
    assert!(!setlocale_sym.is_null());
    assert!(!newlocale_sym.is_null());
    assert!(!wcsftime_l_sym.is_null());
    assert!(!gmtime_r_sym.is_null());

    let setlocale: unsafe extern "C" fn(i32, *const c_char) -> *mut c_char =
        unsafe { std::mem::transmute(setlocale_sym) };
    unsafe {
        setlocale(libc::LC_ALL, c"C".as_ptr());
    }
    let glibc_newlocale: NewLocaleFn = unsafe { std::mem::transmute(newlocale_sym) };
    let c_locale =
        unsafe { glibc_newlocale(libc::LC_ALL_MASK, c"C".as_ptr(), std::ptr::null_mut()) };
    assert!(!c_locale.is_null());

    let glibc_wcsftime_l: WcsftimeLFn = unsafe { std::mem::transmute(wcsftime_l_sym) };
    let glibc_gmtime_r: unsafe extern "C" fn(*const i64, *mut libc::tm) -> *mut libc::tm =
        unsafe { std::mem::transmute(gmtime_r_sym) };

    let epoch: i64 = 1_700_000_000;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { glibc_gmtime_r(&epoch, &mut tm) };
    let tm_ptr = &tm as *const libc::tm;
    let iters = 60_000u64;

    let mut old_buf = [0 as libc::wchar_t; 256];
    let mut new_buf = [0 as libc::wchar_t; 256];
    let mut glibc_buf = [0 as libc::wchar_t; 256];

    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%H:%M",
        "%A",
        "just text no directives",
    ] {
        let wide_fmt = wide_cstr(fmt);
        let fmt_ptr = wide_fmt.as_ptr();

        let old_n = unsafe {
            old_wcsftime_l(
                old_buf.as_mut_ptr(),
                old_buf.len(),
                fmt_ptr,
                tm_ptr as *const c_void,
            )
        };
        let new_n = unsafe {
            wchar_abi::__wcsftime_l(
                new_buf.as_mut_ptr(),
                new_buf.len(),
                fmt_ptr,
                tm_ptr as *const c_void,
                c_locale,
            )
        };
        let glibc_n = unsafe {
            glibc_wcsftime_l(
                glibc_buf.as_mut_ptr(),
                glibc_buf.len(),
                fmt_ptr,
                tm_ptr,
                c_locale,
            )
        };
        assert_eq!(old_n, new_n, "old/new length mismatch for {fmt:?}");
        assert_eq!(new_n, glibc_n, "new/glibc length mismatch for {fmt:?}");
        assert_eq!(
            &old_buf[..old_n],
            &new_buf[..new_n],
            "old/new bytes mismatch for {fmt:?}"
        );
        assert_eq!(
            &new_buf[..new_n],
            &glibc_buf[..glibc_n],
            "new/glibc bytes mismatch for {fmt:?}"
        );

        let (old_t, new_t, glibc_t) = bench3(
            || {
                for _ in 0..iters {
                    black_box(unsafe {
                        old_wcsftime_l(
                            black_box(old_buf.as_mut_ptr()),
                            old_buf.len(),
                            black_box(fmt_ptr),
                            black_box(tm_ptr as *const c_void),
                        )
                    });
                }
            },
            || {
                for _ in 0..iters {
                    black_box(unsafe {
                        wchar_abi::__wcsftime_l(
                            black_box(new_buf.as_mut_ptr()),
                            new_buf.len(),
                            black_box(fmt_ptr),
                            black_box(tm_ptr as *const c_void),
                            c_locale,
                        )
                    });
                }
            },
            || {
                for _ in 0..iters {
                    black_box(unsafe {
                        glibc_wcsftime_l(
                            black_box(glibc_buf.as_mut_ptr()),
                            glibc_buf.len(),
                            black_box(fmt_ptr),
                            black_box(tm_ptr),
                            c_locale,
                        )
                    });
                }
            },
        );

        let old_ns = old_t / iters as f64;
        let new_ns = new_t / iters as f64;
        let glibc_ns = glibc_t / iters as f64;
        let new_old = new_ns / old_ns;
        let new_glibc = new_ns / glibc_ns;
        println!(
            "__wcsftime_l {fmt:<24} old={old_ns:8.2}ns new={new_ns:8.2}ns glibc={glibc_ns:8.2}ns new/old={new_old:.3} {old_tag} new/glibc={new_glibc:.3} {glibc_tag}",
            old_tag = tag(new_old),
            glibc_tag = tag(new_glibc),
        );
    }
}
