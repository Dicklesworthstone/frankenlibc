//! Focused `strftime` no-directive ABI benchmark vs host glibc.

use std::ffi::{CStr, c_char};
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_abi::time_abi;
use frankenlibc_core::time::{BrokenDownTime, format_strftime};

type StrftimeFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, *const libc::tm) -> usize;

fn percentile(samples: &[f64], q: f64) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((q * (sorted.len() - 1) as f64).round() as usize).min(sorted.len() - 1);
    sorted[idx]
}

fn bench2<A, B>(mut a: A, mut b: B) -> (f64, f64)
where
    A: FnMut(),
    B: FnMut(),
{
    let mut aa = Vec::new();
    let mut bb = Vec::new();
    for round in 0..48 {
        if round % 2 == 0 {
            let t = Instant::now();
            a();
            aa.push(t.elapsed().as_nanos() as f64);
            let t = Instant::now();
            b();
            bb.push(t.elapsed().as_nanos() as f64);
        } else {
            let t = Instant::now();
            b();
            bb.push(t.elapsed().as_nanos() as f64);
            let t = Instant::now();
            a();
            aa.push(t.elapsed().as_nanos() as f64);
        }
    }
    (percentile(&aa, 0.10), percentile(&bb, 0.10))
}

fn cstr_bytes(buf: &[c_char]) -> Vec<u8> {
    buf.iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as u8)
        .collect()
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

unsafe fn orig_strftime_literal_path(
    s: *mut c_char,
    maxsize: usize,
    format: *const c_char,
    tm: *const libc::tm,
) -> usize {
    // SAFETY: benchmark inputs are valid C strings.
    let fmt = unsafe { CStr::from_ptr(format).to_bytes() };
    // SAFETY: benchmark passes a valid `libc::tm` pointer.
    let tm = unsafe { *tm };
    let bd = BrokenDownTime {
        tm_sec: tm.tm_sec,
        tm_min: tm.tm_min,
        tm_hour: tm.tm_hour,
        tm_mday: tm.tm_mday,
        tm_mon: tm.tm_mon,
        tm_year: tm.tm_year,
        tm_wday: tm.tm_wday,
        tm_yday: tm.tm_yday,
        tm_isdst: tm.tm_isdst,
        tm_gmtoff: tm.tm_gmtoff,
        zone: [0; 16],
    };
    // SAFETY: benchmark output buffer is valid for `maxsize` bytes.
    let buf = unsafe { std::slice::from_raw_parts_mut(s as *mut u8, maxsize) };
    format_strftime(fmt, &bd, buf)
}

fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let setlocale: unsafe extern "C" fn(i32, *const c_char) -> *mut c_char =
        unsafe { std::mem::transmute(libc::dlsym(h, c"setlocale".as_ptr())) };
    unsafe {
        setlocale(6, c"C".as_ptr());
    }
    let glibc_strftime: StrftimeFn =
        unsafe { std::mem::transmute(libc::dlsym(h, c"strftime".as_ptr())) };

    let epoch: i64 = 1_700_000_000;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { time_abi::gmtime_r(&epoch, &mut tm) };
    let tm_ptr = &tm as *const libc::tm;

    let fmt_c = c"just text no directives";
    let iters = 250_000u64;

    let mut fl = [0 as c_char; 256];
    let mut orig = [0 as c_char; 256];
    let mut glibc = [0 as c_char; 256];
    let fl_n = unsafe { time_abi::strftime(fl.as_mut_ptr(), fl.len(), fmt_c.as_ptr(), tm_ptr) };
    let orig_n = unsafe {
        orig_strftime_literal_path(orig.as_mut_ptr(), orig.len(), fmt_c.as_ptr(), tm_ptr)
    };
    let glibc_n =
        unsafe { glibc_strftime(glibc.as_mut_ptr(), glibc.len(), fmt_c.as_ptr(), tm_ptr) };
    assert_eq!(orig_n, fl_n);
    assert_eq!(fl_n, glibc_n);
    assert_eq!(cstr_bytes(&orig), cstr_bytes(&fl));
    assert_eq!(cstr_bytes(&fl), cstr_bytes(&glibc));

    let (orig_t, fl_t) = bench2(
        || {
            for _ in 0..iters {
                black_box(unsafe {
                    orig_strftime_literal_path(
                        black_box(orig.as_mut_ptr()),
                        orig.len(),
                        black_box(fmt_c.as_ptr()),
                        black_box(tm_ptr),
                    )
                });
            }
        },
        || {
            for _ in 0..iters {
                black_box(unsafe {
                    time_abi::strftime(
                        black_box(fl.as_mut_ptr()),
                        fl.len(),
                        black_box(fmt_c.as_ptr()),
                        black_box(tm_ptr),
                    )
                });
            }
        },
    );
    let (fl_glibc_t, glibc_t) = bench2(
        || {
            for _ in 0..iters {
                black_box(unsafe {
                    time_abi::strftime(
                        black_box(fl.as_mut_ptr()),
                        fl.len(),
                        black_box(fmt_c.as_ptr()),
                        black_box(tm_ptr),
                    )
                });
            }
        },
        || {
            for _ in 0..iters {
                black_box(unsafe {
                    glibc_strftime(
                        black_box(glibc.as_mut_ptr()),
                        glibc.len(),
                        black_box(fmt_c.as_ptr()),
                        black_box(tm_ptr),
                    )
                });
            }
        },
    );
    let orig_ns = orig_t / iters as f64;
    let fl_ns = fl_t / iters as f64;
    let fl_glibc_ns = fl_glibc_t / iters as f64;
    let glibc_ns = glibc_t / iters as f64;
    println!(
        "strftime_abi_literal_orig orig={orig_ns:.2}ns new={fl_ns:.2}ns new/orig={:.3} {} [{}]",
        fl_ns / orig_ns,
        tag(fl_ns / orig_ns),
        String::from_utf8_lossy(&cstr_bytes(&fl))
    );
    println!(
        "strftime_abi_literal_glibc new={fl_glibc_ns:.2}ns glibc={glibc_ns:.2}ns new/glibc={:.3} {} [{}]",
        fl_glibc_ns / glibc_ns,
        tag(fl_glibc_ns / glibc_ns),
        String::from_utf8_lossy(&cstr_bytes(&fl))
    );
}
