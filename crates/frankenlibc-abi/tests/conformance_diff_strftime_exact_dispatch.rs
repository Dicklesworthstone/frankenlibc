//! Conformance gate for the strict-mode exact-format `strftime` dispatcher.
//!
//! The ABI `strftime` recognises a set of complete C-locale formats before the
//! generic scan and directive interpreter: pure literals (SIMD copy), the exact
//! aliases `%R %T %X %r %F %D %x`, the bare names `%a %h`, the numeric dates
//! `%Y-%m-%d %m/%d/%Y %m/%d/%y %d/%m/%Y`, the clocks `%H:%M %H:%M:%S
//! %I:%M:%S %p`, the timestamps `%Y-%m-%d %H:%M:%S %Y%m%d%H%M%S`, and `%c`.
//! Each leaf claims to fall through to the general formatter on non-normalized
//! fields, and to return 0 on a short buffer (`%c` falls through there too).
//! One name inside literals is NOT compiled (the
//! fused single-name lever was rejected on A/B); those formats stay here as
//! general-path controls.
//!
//! This gate checks those claims against live glibc on the same inputs:
//! consistent `tm` values from `gmtime_r` over a wide date range, hand-made
//! out-of-range fields (hour 24, minute 60, second 61, month 12/-1, mday 0/32,
//! wday 7/-1, years that are negative, three-digit and five-digit), and every
//! buffer size from 1 to the full length + 2. On overflow both arms must return
//! 0 (buffer contents are unspecified then, so only the return value is
//! compared).
//!
//! Deliberately NOT in the malformed set: negative hour/minute/second/mday,
//! hour 99 under `%I`, and `tm_year = i32::MAX`. On those, the GENERAL
//! formatter already differs from glibc at the base this gate was written
//! against (258ff4e7d): e.g. `%R` with `tm_hour = -1` gives fl `-01:05` and
//! glibc `-1:05`, and `%Y` with `i32::MAX` wraps differently. The same 64
//! divergences appear with and without the exact dispatcher, so they are not
//! this gate's subject and would only mask a regression in it.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::time_abi::strftime as fl_strftime;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type StrftimeFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, *const libc::tm) -> usize;
type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *mut c_char;

fn host_strftime() -> StrftimeFn {
    // SAFETY: signature matches C's strftime exactly.
    unsafe { dlsym_oracle::host_fn(c"strftime", fl_strftime as *const ()) }
}

fn host_setlocale() -> SetlocaleFn {
    // SAFETY: signature matches C's setlocale exactly.
    unsafe {
        dlsym_oracle::host_fn(
            c"setlocale",
            frankenlibc_abi::locale_abi::setlocale as *const (),
        )
    }
}

fn both_c_locale() {
    // SAFETY: LC_ALL with a NUL-terminated constant, through each arm in turn.
    unsafe {
        host_setlocale()(libc::LC_ALL, c"C".as_ptr());
        frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, c"C".as_ptr());
    }
}

/// Every format the exact dispatcher compiles, plus near misses that must
/// decline to the general formatter.
const FORMATS: &[&str] = &[
    // pure literals (SIMD copy), short and longer than one 32-byte panel
    "",
    "x",
    "literal only",
    "a pure literal format that is longer than thirty-two bytes, twice over!",
    // exact aliases
    "%R",
    "%T",
    "%X",
    "%r",
    "%F",
    "%D",
    "%x",
    "%c",
    // bare names (and the ones that keep their own leaves)
    "%a",
    "%h",
    "%A",
    "%b",
    "%B",
    // numeric families
    "%Y-%m-%d",
    "%m/%d/%Y",
    "%m/%d/%y",
    "%d/%m/%Y",
    "%H:%M",
    "%H:%M:%S",
    "%I:%M:%S %p",
    "%Y-%m-%d %H:%M:%S",
    "%Y%m%d%H%M%S",
    // one name inside literals: general path (fused lever rejected)
    "[%a]",
    "Today is %A.",
    "month=%b;",
    "%B, the month",
    "on %h",
    // near misses: must decline and still match glibc
    "%Y-%m-%d ",
    "%H:%M:%S ",
    "%I:%M:%S",
    "%m/%d/%Yx",
    "%d/%m/%y",
    "%a %b",
    "%a%%",
    "x%Rx",
    "%cx",
];

fn render(f: StrftimeFn, fmt: &CString, tm: &libc::tm, size: usize) -> (usize, Vec<u8>) {
    // A canary-filled buffer one byte larger than `size`, so an over-write past
    // `size` would show up in the trailing byte.
    let mut buf = vec![0xA5u8; size + 1];
    // SAFETY: `buf` holds at least `size` writable bytes; `fmt` is NUL-terminated.
    let n = unsafe { f(buf.as_mut_ptr().cast(), size, fmt.as_ptr(), tm) };
    assert_eq!(buf[size], 0xA5, "strftime wrote past maxsize={size}");
    (n, buf[..n.min(size)].to_vec())
}

fn compare(fmt: &str, tm: &libc::tm, divs: &mut Vec<String>) -> usize {
    let cf = CString::new(fmt).unwrap();
    let host = host_strftime();
    let (full_n, full) = render(host, &cf, tm, 256);
    let (fl_full_n, fl_full) = render(fl_strftime, &cf, tm, 256);
    let mut compared = 1;
    if (fl_full_n, &fl_full) != (full_n, &full) {
        divs.push(format!(
            "fmt={fmt:?} tm={}: fl=(n={fl_full_n}, {:?}) glibc=(n={full_n}, {:?})",
            describe(tm),
            String::from_utf8_lossy(&fl_full),
            String::from_utf8_lossy(&full),
        ));
        return compared;
    }
    // Every buffer size around the boundary: only the return value is
    // specified on overflow, the bytes as well when the result fits.
    for size in 1..=full_n + 2 {
        let (gn, gs) = render(host, &cf, tm, size);
        let (fn_, fs) = render(fl_strftime, &cf, tm, size);
        compared += 1;
        let agree = if gn == 0 {
            fn_ == 0
        } else {
            (fn_, &fs) == (gn, &gs)
        };
        if !agree {
            divs.push(format!(
                "fmt={fmt:?} tm={} maxsize={size}: fl=(n={fn_}, {:?}) glibc=(n={gn}, {:?})",
                describe(tm),
                String::from_utf8_lossy(&fs),
                String::from_utf8_lossy(&gs),
            ));
            break;
        }
    }
    compared
}

fn describe(tm: &libc::tm) -> String {
    format!(
        "{{y={} mon={} mday={} h={} m={} s={} wday={} yday={}}}",
        tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_wday, tm.tm_yday
    )
}

fn consistent_tms() -> Vec<libc::tm> {
    unsafe extern "C" {
        fn gmtime_r(t: *const libc::time_t, tm: *mut libc::tm) -> *mut libc::tm;
    }
    let mut out = Vec::new();
    let mut state = 0x005e_ed0f_d15b_a7c4_u64;
    let mut epochs: Vec<libc::time_t> = vec![
        0,
        -1,
        951_782_400,     // 2000-02-29
        1_700_000_000,   // 2023-11-14 22:13:20
        1_704_067_199,   // 2023-12-31 23:59:59
        43_200,          // noon: 12-hour clock boundary
        3_600 * 13,      // 13:00
        -62_135_596_800, // 0001-01-01
        253_402_300_799, // 9999-12-31 23:59:59
        253_402_300_800, // 10000-01-01: five-digit year
        -62_198_755_200, // year 0 (glibc %Y prints "0")
        -62_230_291_200, // year -1
    ];
    for _ in 0..200 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        epochs.push(((state >> 11) % 8_000_000_000) as i64 - 2_000_000_000);
    }
    for epoch in epochs {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        // SAFETY: valid in/out pointers.
        if !unsafe { gmtime_r(&epoch, &mut tm) }.is_null() {
            out.push(tm);
        }
    }
    out
}

fn malformed_tms() -> Vec<libc::tm> {
    let mut base: libc::tm = unsafe { std::mem::zeroed() };
    base.tm_year = 124;
    base.tm_mon = 6;
    base.tm_mday = 14;
    base.tm_hour = 9;
    base.tm_min = 5;
    base.tm_sec = 7;
    base.tm_wday = 0;
    base.tm_yday = 195;
    let mut out = Vec::new();
    let edits: &[fn(&mut libc::tm)] = &[
        |t| t.tm_hour = 24,
        |t| t.tm_hour = 0,
        |t| t.tm_hour = 12,
        |t| t.tm_min = 60,
        |t| t.tm_sec = 60,
        |t| t.tm_sec = 61,
        |t| t.tm_mon = 12,
        |t| t.tm_mon = -1,
        |t| t.tm_mday = 0,
        |t| t.tm_mday = 32,
        |t| t.tm_wday = 7,
        |t| t.tm_wday = -1,
        |t| t.tm_year = -1900,
        |t| t.tm_year = -1901,
        |t| t.tm_year = -2000,
        |t| t.tm_year = -1800,
        |t| t.tm_year = 8100,
        |t| t.tm_year = 10_000,
        |t| t.tm_year = i32::MIN,
    ];
    for edit in edits {
        let mut t = base;
        edit(&mut t);
        out.push(t);
    }
    out
}

#[test]
fn strftime_exact_dispatch_matches_glibc() {
    both_c_locale();
    let mut divs = Vec::new();
    let mut compared = 0usize;
    let tms: Vec<libc::tm> = consistent_tms()
        .into_iter()
        .chain(malformed_tms())
        .collect();
    for tm in &tms {
        for fmt in FORMATS {
            compared += compare(fmt, tm, &mut divs);
        }
    }
    assert!(compared > 10_000, "only {compared} comparisons ran");
    assert!(
        divs.is_empty(),
        "{} of {compared} strftime comparisons diverged from live glibc (first 40):\n{}",
        divs.len(),
        divs.iter().take(40).cloned().collect::<Vec<_>>().join("\n")
    );
}

/// glibc renders a bare name or a whole-format alias (`%D` and friends expand
/// as one sub-format) as a single unit: when it does not fit with its
/// terminator, glibc returns 0 without writing a byte. The exact leaves do the
/// same for normalized fields, so for these formats the whole canary-filled
/// destination must match glibc on overflow, not only the return value.
/// `conformance_diff_strftime_l` pins the same contract for `%A`, `%b`, `%B`.
#[test]
fn exact_leaves_leave_the_destination_untouched_on_overflow() {
    both_c_locale();
    const UNIT_FORMATS: &[&str] = &[
        "%a", "%h", "%A", "%b", "%B", "%R", "%T", "%X", "%r", "%F", "%D", "%x",
    ];
    let host = host_strftime();
    let mut divs = Vec::new();
    let mut compared = 0usize;
    for tm in consistent_tms()
        .iter()
        .filter(|tm| (1000 - 1900..=9999 - 1900).contains(&tm.tm_year))
    {
        for fmt in UNIT_FORMATS {
            let cf = CString::new(*fmt).unwrap();
            let (full_n, _) = render(host, &cf, tm, 256);
            for size in 1..=full_n {
                let mut fl_buf = vec![0xA5u8; size + 1];
                let mut glibc_buf = vec![0xA5u8; size + 1];
                // SAFETY: each buffer holds `size + 1` writable bytes and `cf`
                // is NUL-terminated.
                let (fl_n, glibc_n) = unsafe {
                    (
                        fl_strftime(fl_buf.as_mut_ptr().cast(), size, cf.as_ptr(), tm),
                        host(glibc_buf.as_mut_ptr().cast(), size, cf.as_ptr(), tm),
                    )
                };
                compared += 1;
                if (fl_n, &fl_buf) != (glibc_n, &glibc_buf) {
                    divs.push(format!(
                        "fmt={fmt:?} tm={} maxsize={size}: fl=(n={fl_n}, {fl_buf:x?}) \
                         glibc=(n={glibc_n}, {glibc_buf:x?})",
                        describe(tm)
                    ));
                    break;
                }
            }
        }
    }
    assert!(compared > 1_000, "only {compared} comparisons ran");
    assert!(
        divs.is_empty(),
        "{} overflow destinations differ from live glibc (first 40):\n{}",
        divs.len(),
        divs.iter().take(40).cloned().collect::<Vec<_>>().join("\n")
    );
}
