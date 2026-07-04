//! In-process A/B for the wcsftime wide/narrow transcode path.
//!
//! ORIG embeds the previous heap-buffer implementation so the benchmark can
//! compare current code against the exact pre-change algorithm in one binary.

use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_abi::{time_abi, wchar_abi};
use frankenlibc_core::string::wchar as wchar_core;

type WcsftimeFn =
    unsafe extern "C" fn(*mut libc::wchar_t, usize, *const libc::wchar_t, *const libc::tm) -> usize;

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

unsafe fn wide_len(mut p: *const libc::wchar_t) -> usize {
    let mut len = 0usize;
    while unsafe { *p } != 0 {
        len += 1;
        p = unsafe { p.add(1) };
    }
    len
}

unsafe fn orig_wcsftime(
    s: *mut libc::wchar_t,
    maxsize: usize,
    format: *const libc::wchar_t,
    tm: *const c_void,
) -> usize {
    if s.is_null() || format.is_null() || tm.is_null() || maxsize == 0 {
        return 0;
    }

    let fmt_len = unsafe { wide_len(format) };
    let fmt_slice = unsafe { std::slice::from_raw_parts(format as *const u32, fmt_len) };

    let mut fmt_mb = Vec::with_capacity(fmt_len.saturating_mul(6).saturating_add(1));
    for &wc in fmt_slice {
        let mut tmp = [0u8; 6];
        let Some(n) = wchar_core::wctomb(wc, &mut tmp) else {
            return 0;
        };
        fmt_mb.extend_from_slice(&tmp[..n]);
    }
    fmt_mb.push(0);

    let mut out_mb = vec![0u8; maxsize.saturating_mul(6).max(1)];
    let out_len = unsafe {
        time_abi::strftime(
            out_mb.as_mut_ptr() as *mut std::ffi::c_char,
            out_mb.len(),
            fmt_mb.as_ptr() as *const std::ffi::c_char,
            tm as *const libc::tm,
        )
    };
    if out_len == 0 {
        return 0;
    }

    let mut mb_i = 0usize;
    let mut wide_i = 0usize;
    while mb_i < out_len {
        if wide_i.saturating_add(1) >= maxsize {
            return 0;
        }
        match wchar_core::mbtowc(&out_mb[mb_i..out_len]) {
            Some((wc, used)) => {
                unsafe { *s.add(wide_i) = wc as libc::wchar_t };
                wide_i += 1;
                mb_i += used;
            }
            None => return 0,
        }
    }

    unsafe { *s.add(wide_i) = 0 };
    wide_i
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
    let glibc_wcsftime: WcsftimeFn =
        unsafe { std::mem::transmute(libc::dlsym(libc_handle, c"wcsftime".as_ptr())) };

    let epoch: i64 = 1_700_000_000;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { time_abi::gmtime_r(&epoch, &mut tm) };
    let tm_ptr = &tm as *const libc::tm;

    let iters = 80_000u64;
    let mut orig_buf = [0 as libc::wchar_t; 256];
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

        let orig_n = unsafe {
            orig_wcsftime(
                orig_buf.as_mut_ptr(),
                orig_buf.len(),
                fmt_ptr,
                tm_ptr as *const c_void,
            )
        };
        let new_n = unsafe {
            wchar_abi::wcsftime(
                new_buf.as_mut_ptr(),
                new_buf.len(),
                fmt_ptr,
                tm_ptr as *const c_void,
            )
        };
        let glibc_n =
            unsafe { glibc_wcsftime(glibc_buf.as_mut_ptr(), glibc_buf.len(), fmt_ptr, tm_ptr) };
        let matches_orig =
            orig_n == new_n && orig_buf[..orig_n] == new_buf[..new_n] && new_n == glibc_n;
        let matches_glibc = new_buf[..new_n] == glibc_buf[..glibc_n];
        assert!(
            matches_orig && matches_glibc,
            "wcsftime output mismatch for {fmt:?}"
        );

        let (orig_t, new_t, glibc_t) = bench3(
            || {
                for _ in 0..iters {
                    black_box(unsafe {
                        orig_wcsftime(
                            black_box(orig_buf.as_mut_ptr()),
                            orig_buf.len(),
                            black_box(fmt_ptr),
                            black_box(tm_ptr as *const c_void),
                        )
                    });
                }
            },
            || {
                for _ in 0..iters {
                    black_box(unsafe {
                        wchar_abi::wcsftime(
                            black_box(new_buf.as_mut_ptr()),
                            new_buf.len(),
                            black_box(fmt_ptr),
                            black_box(tm_ptr as *const c_void),
                        )
                    });
                }
            },
            || {
                for _ in 0..iters {
                    black_box(unsafe {
                        glibc_wcsftime(
                            black_box(glibc_buf.as_mut_ptr()),
                            glibc_buf.len(),
                            black_box(fmt_ptr),
                            black_box(tm_ptr),
                        )
                    });
                }
            },
        );

        let orig_ns = orig_t / iters as f64;
        let new_ns = new_t / iters as f64;
        let glibc_ns = glibc_t / iters as f64;
        let new_orig = new_ns / orig_ns;
        let new_glibc = new_ns / glibc_ns;
        println!(
            "wcsftime {fmt:<24} orig={orig_ns:8.2}ns new={new_ns:8.2}ns glibc={glibc_ns:8.2}ns new/orig={new_orig:.3} {orig_tag} new/glibc={new_glibc:.3} {glibc_tag}",
            orig_tag = tag(new_orig),
            glibc_tag = tag(new_glibc),
        );
    }
}
