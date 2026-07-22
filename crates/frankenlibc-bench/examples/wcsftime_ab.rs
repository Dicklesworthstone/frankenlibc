//! Same-worker interleaved A/B for exact `%FT%T` `wcsftime`.
//!
//! `orig_wcsftime` reconstructs the deployed general wide->narrow->wide bridge.
//! The candidate is the deployed symbol. A source-identical candidate/candidate
//! NULL control is timed in every retained sample.

use std::ffi::{c_char, c_void};
use std::hint::black_box;
use std::time::{Duration, Instant};

use frankenlibc_abi::{time_abi, wchar_abi};
use frankenlibc_core::string::wchar as wchar_core;

const SAMPLES: usize = 80;
const WARMUP: usize = 16;
const REPS: usize = 5_000_000;
const FORMAT: &str = "%FT%T";

type WcsftimeFn =
    unsafe extern "C" fn(*mut libc::wchar_t, usize, *const libc::wchar_t, *const libc::tm) -> usize;

fn median(xs: &[f64]) -> f64 {
    let mut values = xs.to_vec();
    values.sort_by(|a, b| a.partial_cmp(b).expect("no NaN timings"));
    let mid = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

fn cv_pct(xs: &[f64]) -> f64 {
    let avg = mean(xs);
    let variance = xs
        .iter()
        .map(|value| (value - avg) * (value - avg))
        .sum::<f64>()
        / xs.len() as f64;
    100.0 * variance.sqrt() / avg
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
        // SAFETY: the caller supplies a NUL-terminated wide string.
        p = unsafe { p.add(1) };
    }
    len
}

/// The deployed pre-lever general bridge, retained in the same binary for A/B.
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
    let fmt_slice = unsafe { std::slice::from_raw_parts(format.cast::<u32>(), fmt_len) };

    const FMT_STACK: usize = 512;
    let fmt_budget = fmt_len.saturating_mul(6).saturating_add(1);
    let mut fmt_stack = [0u8; FMT_STACK];
    let mut fmt_heap = Vec::new();
    let use_fmt_stack = fmt_budget <= FMT_STACK;
    {
        let buf: &mut [u8] = if use_fmt_stack {
            &mut fmt_stack
        } else {
            fmt_heap = vec![0u8; fmt_budget];
            &mut fmt_heap
        };
        let mut written = 0usize;
        for &wc in fmt_slice {
            if wc < 0x80 {
                buf[written] = wc as u8;
                written += 1;
                continue;
            }
            let mut tmp = [0u8; 6];
            let Some(n) = wchar_core::wctomb(wc, &mut tmp) else {
                return 0;
            };
            buf[written..written + n].copy_from_slice(&tmp[..n]);
            written += n;
        }
        buf[written] = 0;
    }
    let fmt_ptr = if use_fmt_stack {
        fmt_stack.as_ptr()
    } else {
        fmt_heap.as_ptr()
    }
    .cast::<c_char>();

    const OUT_STACK: usize = 1024;
    let out_budget = maxsize.saturating_mul(6).max(1);
    let mut out_stack = [0u8; OUT_STACK];
    let mut out_heap: Vec<u8>;
    let stack_cap = out_budget.min(OUT_STACK);
    let mut out_len = unsafe {
        time_abi::strftime(
            out_stack.as_mut_ptr().cast::<c_char>(),
            stack_cap,
            fmt_ptr,
            tm.cast::<libc::tm>(),
        )
    };
    let out_ptr = if out_len > 0 {
        out_stack.as_ptr()
    } else if out_budget > OUT_STACK {
        out_heap = vec![0u8; out_budget];
        out_len = unsafe {
            time_abi::strftime(
                out_heap.as_mut_ptr().cast::<c_char>(),
                out_heap.len(),
                fmt_ptr,
                tm.cast::<libc::tm>(),
            )
        };
        if out_len == 0 {
            return 0;
        }
        out_heap.as_ptr()
    } else {
        return 0;
    };
    let out_mb = unsafe { std::slice::from_raw_parts(out_ptr, out_len) };

    let mut mb_i = 0usize;
    let mut wide_i = 0usize;
    while mb_i < out_len {
        if wide_i.saturating_add(1) >= maxsize {
            return 0;
        }
        let b0 = out_mb[mb_i];
        if b0 < 0x80 {
            unsafe { *s.add(wide_i) = b0 as libc::wchar_t };
            wide_i += 1;
            mb_i += 1;
            continue;
        }
        let Some((wc, used)) = wchar_core::mbtowc(&out_mb[mb_i..out_len]) else {
            return 0;
        };
        unsafe { *s.add(wide_i) = wc as libc::wchar_t };
        wide_i += 1;
        mb_i += used;
    }

    unsafe { *s.add(wide_i) = 0 };
    wide_i
}

#[inline(never)]
fn run_orig(out: *mut libc::wchar_t, fmt: *const libc::wchar_t, tm: *const libc::tm) -> usize {
    let mut total = 0usize;
    for _ in 0..REPS {
        total = total.wrapping_add(black_box(unsafe {
            orig_wcsftime(
                black_box(out),
                64,
                black_box(fmt),
                black_box(tm.cast::<c_void>()),
            )
        }));
    }
    black_box(total)
}

#[inline(never)]
fn run_candidate(out: *mut libc::wchar_t, fmt: *const libc::wchar_t, tm: *const libc::tm) -> usize {
    let mut total = 0usize;
    for _ in 0..REPS {
        total = total.wrapping_add(black_box(unsafe {
            wchar_abi::wcsftime(
                black_box(out),
                64,
                black_box(fmt),
                black_box(tm.cast::<c_void>()),
            )
        }));
    }
    black_box(total)
}

#[inline(never)]
fn run_host(
    host: WcsftimeFn,
    out: *mut libc::wchar_t,
    fmt: *const libc::wchar_t,
    tm: *const libc::tm,
) -> usize {
    let mut total = 0usize;
    for _ in 0..REPS {
        total = total.wrapping_add(black_box(unsafe {
            host(black_box(out), 64, black_box(fmt), black_box(tm))
        }));
    }
    black_box(total)
}

fn timed(f: impl FnOnce() -> usize) -> Duration {
    let start = Instant::now();
    black_box(f());
    start.elapsed()
}

fn assert_case(
    host: WcsftimeFn,
    fmt: *const libc::wchar_t,
    tm: &libc::tm,
    capacity: usize,
    compare_host: bool,
) {
    let mut orig = [0x5555 as libc::wchar_t; 64];
    let mut candidate = [0x5555 as libc::wchar_t; 64];
    let mut glibc = [0x5555 as libc::wchar_t; 64];
    let orig_n = unsafe {
        orig_wcsftime(
            orig.as_mut_ptr(),
            capacity,
            fmt,
            std::ptr::from_ref(tm).cast::<c_void>(),
        )
    };
    let candidate_n = unsafe {
        wchar_abi::wcsftime(
            candidate.as_mut_ptr(),
            capacity,
            fmt,
            std::ptr::from_ref(tm).cast::<c_void>(),
        )
    };
    let host_n = unsafe { host(glibc.as_mut_ptr(), capacity, fmt, tm) };
    assert_eq!(candidate_n, orig_n, "candidate/orig length cap={capacity}");
    if compare_host {
        assert_eq!(candidate_n, host_n, "candidate/glibc length cap={capacity}");
    }
    if candidate_n != 0 {
        assert_eq!(
            &candidate[..=candidate_n],
            &orig[..=orig_n],
            "candidate/orig bytes cap={capacity}"
        );
        if compare_host {
            assert_eq!(
                &candidate[..=candidate_n],
                &glibc[..=host_n],
                "candidate/glibc bytes cap={capacity}"
            );
        }
    }
}

fn verify(host: WcsftimeFn, fmt: *const libc::wchar_t) -> libc::tm {
    let mut valid: libc::tm = unsafe { std::mem::zeroed() };
    valid.tm_year = 123;
    valid.tm_mon = 10;
    valid.tm_mday = 14;
    valid.tm_hour = 22;
    valid.tm_min = 13;
    valid.tm_sec = 20;
    for capacity in 1..=24 {
        assert_case(host, fmt, &valid, capacity, true);
    }
    for (field, value) in [
        (0, -900),
        (0, 8099),
        (1, 0),
        (1, 11),
        (2, 1),
        (2, 31),
        (3, 0),
        (3, 23),
        (4, 0),
        (4, 59),
        (5, 0),
        (5, 60),
    ] {
        let mut tm = valid;
        match field {
            0 => tm.tm_year = value,
            1 => tm.tm_mon = value,
            2 => tm.tm_mday = value,
            3 => tm.tm_hour = value,
            4 => tm.tm_min = value,
            5 => tm.tm_sec = value,
            _ => unreachable!(),
        }
        assert_case(host, fmt, &tm, 64, true);
    }

    let mut cases = Vec::new();
    for (field, value) in [
        (0, -901),
        (0, 8100),
        (1, -1),
        (1, 12),
        (2, 0),
        (2, 32),
        (3, -1),
        (3, 24),
        (4, -1),
        (4, 60),
        (5, -1),
        (5, 61),
    ] {
        let mut tm = valid;
        match field {
            0 => tm.tm_year = value,
            1 => tm.tm_mon = value,
            2 => tm.tm_mday = value,
            3 => tm.tm_hour = value,
            4 => tm.tm_min = value,
            5 => tm.tm_sec = value,
            _ => unreachable!(),
        }
        cases.push(tm);
    }
    for tm in &cases {
        assert_case(host, fmt, tm, 64, false);
    }
    println!(
        "verify: OK (candidate == host glibc for valid %FT%T boundaries; candidate == ORIG for invalid-field fallbacks)"
    );
    valid
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
    let host: WcsftimeFn = unsafe {
        let symbol = libc::dlsym(libc_handle, c"wcsftime".as_ptr());
        assert!(!symbol.is_null());
        std::mem::transmute(symbol)
    };
    let format = wide_cstr(FORMAT);
    let fmt = format.as_ptr();
    let tm = verify(host, fmt);
    let tm_ptr = std::ptr::from_ref(&tm);

    let mut orig_out = [0 as libc::wchar_t; 64];
    let mut candidate_out = [0 as libc::wchar_t; 64];
    let mut host_out = [0 as libc::wchar_t; 64];
    let mut orig = Vec::with_capacity(SAMPLES - WARMUP);
    let mut candidate = Vec::with_capacity(SAMPLES - WARMUP);
    let mut glibc = Vec::with_capacity(SAMPLES - WARMUP);
    let mut null_a = Vec::with_capacity(SAMPLES - WARMUP);
    let mut null_b = Vec::with_capacity(SAMPLES - WARMUP);

    for sample in 0..SAMPLES {
        let (orig_elapsed, candidate_elapsed, host_elapsed, null_a_elapsed, null_b_elapsed) =
            if sample % 2 == 0 {
                let na = timed(|| run_candidate(candidate_out.as_mut_ptr(), fmt, tm_ptr));
                let old = timed(|| run_orig(orig_out.as_mut_ptr(), fmt, tm_ptr));
                let host_t = timed(|| run_host(host, host_out.as_mut_ptr(), fmt, tm_ptr));
                let new = timed(|| run_candidate(candidate_out.as_mut_ptr(), fmt, tm_ptr));
                let nb = timed(|| run_candidate(candidate_out.as_mut_ptr(), fmt, tm_ptr));
                (old, new, host_t, na, nb)
            } else {
                let nb = timed(|| run_candidate(candidate_out.as_mut_ptr(), fmt, tm_ptr));
                let new = timed(|| run_candidate(candidate_out.as_mut_ptr(), fmt, tm_ptr));
                let host_t = timed(|| run_host(host, host_out.as_mut_ptr(), fmt, tm_ptr));
                let old = timed(|| run_orig(orig_out.as_mut_ptr(), fmt, tm_ptr));
                let na = timed(|| run_candidate(candidate_out.as_mut_ptr(), fmt, tm_ptr));
                (old, new, host_t, na, nb)
            };

        if sample >= WARMUP {
            let scale = REPS as f64;
            orig.push(orig_elapsed.as_nanos() as f64 / scale);
            candidate.push(candidate_elapsed.as_nanos() as f64 / scale);
            glibc.push(host_elapsed.as_nanos() as f64 / scale);
            null_a.push(null_a_elapsed.as_nanos() as f64 / scale);
            null_b.push(null_b_elapsed.as_nanos() as f64 / scale);
        }
    }

    let paired: Vec<f64> = candidate
        .iter()
        .zip(&orig)
        .map(|(candidate_ns, orig_ns)| candidate_ns / orig_ns)
        .collect();
    let host_paired: Vec<f64> = candidate
        .iter()
        .zip(&glibc)
        .map(|(candidate_ns, host_ns)| candidate_ns / host_ns)
        .collect();
    let null_paired: Vec<f64> = null_b
        .iter()
        .zip(&null_a)
        .map(|(b_ns, a_ns)| b_ns / a_ns)
        .collect();
    println!(
        "WCSFTIME_FT_T_AB samples={} reps/arm={REPS} (interleaved, order alternated)",
        orig.len()
    );
    println!(
        "  orig(general bridge) median {:8.2} ns/call  mean {:8.2}  cv={:5.2}%",
        median(&orig),
        mean(&orig),
        cv_pct(&orig)
    );
    println!(
        "  candidate            median {:8.2} ns/call  mean {:8.2}  cv={:5.2}%",
        median(&candidate),
        mean(&candidate),
        cv_pct(&candidate)
    );
    println!(
        "  host glibc            median {:8.2} ns/call  mean {:8.2}  cv={:5.2}%",
        median(&glibc),
        mean(&glibc),
        cv_pct(&glibc)
    );
    println!(
        "  NULL candidate/candidate: median {:.4}  cv={:.2}%  arms cv={:.2}%/{:.2}%",
        median(&null_paired),
        cv_pct(&null_paired),
        cv_pct(&null_a),
        cv_pct(&null_b)
    );
    println!(
        "  PAIRED candidate/orig: median {:.4} ({:.2}x faster)  cv={:.2}%",
        median(&paired),
        1.0 / median(&paired),
        cv_pct(&paired)
    );
    println!(
        "  PAIRED candidate/glibc: median {:.4}  cv={:.2}%  verdict={}",
        median(&host_paired),
        cv_pct(&host_paired),
        if median(&host_paired) <= 1.0 {
            "WIN"
        } else {
            "LOSS"
        }
    );
}
