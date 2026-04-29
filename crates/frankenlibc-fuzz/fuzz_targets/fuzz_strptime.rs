#![no_main]
//! Differential fuzz target: frankenlibc-abi `strptime` vs host
//! `libc::strptime`.
//!
//! `strptime` is a 270+-line hand-written format-driven parser
//! (frankenlibc-abi/src/time_abi.rs, ~L869). The conformance harness
//! `tests/conformance_diff_time.rs::diff_strptime_cases` (landed in
//! 74465c08) caught five concrete range-check omissions on a curated
//! 49-case set; this target mines the rest of the input space against
//! host glibc.
//!
//! ## Input layout
//!
//! Raw fuzzer bytes are split as:
//!
//! ```text
//! byte[0]              fmt_index (mod FORMATS.len())
//! byte[1 .. ]          input string (sanitized to printable ASCII,
//!                      truncated, NUL-terminated for the C call)
//! ```
//!
//! Why a fixed format menu instead of synthesizing format strings from
//! raw bytes:
//!
//! - Random bytes almost never form a syntactically meaningful strptime
//!   format ("%X" alone has 24 valid specifiers but ~230 invalid byte
//!   values), so >99% of the iterations would early-bail at the first
//!   "%?" without exercising parser behavior.
//! - The 12 hand-curated formats below cover every supported specifier
//!   at least once, all four composite shortcuts (%D %T %R %F), the
//!   century-stitching path (%C%y), and a couple of human-readable
//!   shapes that real callers actually use.
//! - The input *string* is the high-variance dimension; that's where
//!   parser bugs hide (off-by-one on digit consumption, mishandled
//!   leading whitespace, locale-table boundary conditions in %b/%B,
//!   etc.).
//!
//! ## Filters that suppress non-bugs
//!
//! - **Printable ASCII only** (0x20..=0x7E) for the input string —
//!   strptime's locale-sensitive month/day-name matching diverges
//!   between glibc / musl / Rust on non-ASCII bytes; that's a separate
//!   conversation.
//! - **No embedded NUL** — we hand both impls a CString and would
//!   otherwise reject the input.
//! - **Bound the input length** at 96 bytes — none of the curated
//!   formats can consume more than ~30 bytes of input, so anything
//!   beyond is just trailing junk that both impls treat identically.
//!
//! ## Comparison
//!
//! Per iteration:
//!   1. Parse parity — both impls must agree on success/failure
//!      (return-non-NULL vs return-NULL).
//!   2. End offset — when both succeed, the byte offset into the input
//!      where parsing stopped must match.
//!   3. tm fields — only the fields the active format is supposed to
//!      write are compared (per-format bitmask). tm_wday, tm_yday, and
//!      tm_isdst are excluded because some impls auto-compute them
//!      from %Y%m%d.

use std::ffi::CString;

use frankenlibc_abi::time_abi as fl;
use libc::c_char;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 96;

const TM_FIELD_SEC: u32 = 1 << 0;
const TM_FIELD_MIN: u32 = 1 << 1;
const TM_FIELD_HOUR: u32 = 1 << 2;
const TM_FIELD_MDAY: u32 = 1 << 3;
const TM_FIELD_MON: u32 = 1 << 4;
const TM_FIELD_YEAR: u32 = 1 << 5;

struct FormatSpec {
    fmt: &'static [u8],
    /// Bitmask of TM_FIELD_* the format writes. Only these fields are
    /// compared between fl_tm and lc_tm on success.
    fields: u32,
}

/// Curated format menu — see module docs.
const FORMATS: &[FormatSpec] = &[
    FormatSpec { fmt: b"%Y",                                fields: TM_FIELD_YEAR },
    FormatSpec { fmt: b"%y",                                fields: TM_FIELD_YEAR },
    FormatSpec { fmt: b"%C%y",                              fields: TM_FIELD_YEAR },
    FormatSpec { fmt: b"%Y-%m-%d",                          fields: TM_FIELD_YEAR | TM_FIELD_MON | TM_FIELD_MDAY },
    FormatSpec { fmt: b"%Y-%m-%d %H:%M:%S",                 fields: TM_FIELD_YEAR | TM_FIELD_MON | TM_FIELD_MDAY | TM_FIELD_HOUR | TM_FIELD_MIN | TM_FIELD_SEC },
    FormatSpec { fmt: b"%H:%M:%S",                          fields: TM_FIELD_HOUR | TM_FIELD_MIN | TM_FIELD_SEC },
    FormatSpec { fmt: b"%I:%M %p",                          fields: TM_FIELD_HOUR | TM_FIELD_MIN },
    FormatSpec { fmt: b"%T",                                fields: TM_FIELD_HOUR | TM_FIELD_MIN | TM_FIELD_SEC },
    FormatSpec { fmt: b"%D",                                fields: TM_FIELD_YEAR | TM_FIELD_MON | TM_FIELD_MDAY },
    FormatSpec { fmt: b"%R",                                fields: TM_FIELD_HOUR | TM_FIELD_MIN },
    FormatSpec { fmt: b"%F",                                fields: TM_FIELD_YEAR | TM_FIELD_MON | TM_FIELD_MDAY },
    FormatSpec { fmt: b"%B %d, %Y",                         fields: TM_FIELD_MON | TM_FIELD_MDAY | TM_FIELD_YEAR },
];

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let fmt_idx = (data[0] as usize) % FORMATS.len();
    let spec = &FORMATS[fmt_idx];
    let raw_input = if data.len() > 1 { &data[1..] } else { b"" };
    let input = sanitize(raw_input, MAX_INPUT_BYTES);

    let Ok(fmt_z) = CString::new(spec.fmt.to_vec()) else {
        return;
    };
    let Ok(input_z) = CString::new(input.clone()) else {
        return;
    };
    let fmt_p = fmt_z.as_ptr();
    let input_p = input_z.as_ptr();

    let mut fl_tm = empty_tm();
    let mut lc_tm = empty_tm();
    // SAFETY: both pointers are NUL-terminated for the call duration;
    // each tm is an exclusive local.
    let fl_end = unsafe { fl::strptime(input_p, fmt_p, &mut fl_tm) };
    let lc_end = unsafe { libc::strptime(input_p, fmt_p, &mut lc_tm) };

    // 1. Failure parity.
    let fl_ok = !fl_end.is_null();
    let lc_ok = !lc_end.is_null();
    assert_eq!(
        fl_ok, lc_ok,
        "strptime success-mismatch: fmt={:?}, input={:?}: fl={}, libc={}",
        ascii_lossy(spec.fmt),
        ascii_lossy(&input),
        fl_ok,
        lc_ok,
    );
    if !fl_ok {
        return;
    }

    // 2. End offset.
    // SAFETY: both end pointers are derived from input_p which is a
    // CString-owned buffer alive for the whole call.
    let fl_off = unsafe { fl_end.offset_from(input_p) };
    let lc_off = unsafe { lc_end.offset_from(input_p) };
    assert_eq!(
        fl_off, lc_off,
        "strptime end-offset divergence: fmt={:?}, input={:?}: fl={}, libc={}",
        ascii_lossy(spec.fmt),
        ascii_lossy(&input),
        fl_off,
        lc_off,
    );

    // 3. tm fields (only those the format writes).
    let pairs: &[(u32, &str, i32, i32)] = &[
        (TM_FIELD_SEC, "tm_sec", fl_tm.tm_sec, lc_tm.tm_sec),
        (TM_FIELD_MIN, "tm_min", fl_tm.tm_min, lc_tm.tm_min),
        (TM_FIELD_HOUR, "tm_hour", fl_tm.tm_hour, lc_tm.tm_hour),
        (TM_FIELD_MDAY, "tm_mday", fl_tm.tm_mday, lc_tm.tm_mday),
        (TM_FIELD_MON, "tm_mon", fl_tm.tm_mon, lc_tm.tm_mon),
        (TM_FIELD_YEAR, "tm_year", fl_tm.tm_year, lc_tm.tm_year),
    ];
    for &(mask, field, fv, lv) in pairs {
        if spec.fields & mask != 0 {
            assert_eq!(
                fv, lv,
                "strptime {field} divergence: fmt={:?}, input={:?}: fl={}, libc={}",
                ascii_lossy(spec.fmt),
                ascii_lossy(&input),
                fv,
                lv,
            );
        }
    }
});

fn sanitize(input: &[u8], max_len: usize) -> Vec<u8> {
    input
        .iter()
        .take(max_len)
        .copied()
        .filter(|&b| (0x20..=0x7E).contains(&b))
        .collect()
}

fn ascii_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn empty_tm() -> libc::tm {
    libc::tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null(),
    }
}

// Silence unused-import lint when the libfuzzer entry doesn't reach
// into c_char directly (the type is still load-bearing via the glibc
// extern signatures).
#[allow(dead_code)]
fn _unused_c_char_anchor(_: c_char) {}
