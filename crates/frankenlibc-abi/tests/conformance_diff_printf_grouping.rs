#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live glibc snprintf/setlocale oracle

//! The printf `'` flag against live glibc under a named LC_NUMERIC.
//!
//! ## What was wrong (bd-rc0923-epic-eeuy4f.10)
//!
//! fl parsed `'` and never applied it: under `en_US.UTF-8`, `%'d` of 1234567
//! printed `1234567` where glibc prints `1,234,567`. Every case below that
//! groups at all failed before the fix; the rows that do not group (C locale,
//! `%e`, `%a`, short numbers) pin that the flag changes nothing else.
//!
//! glibc's rules, as observed on the host: the SIGNIFICANT digits are grouped
//! in every integer base (`%'x` too); precision zeros and zero padding are
//! not, and the separators count toward the width; `%f`/`%F`/`%g`/`%G` group
//! the integer part, `%e`/`%a` do not.
//!
//! Skipped, with the reason printed, when the host has no `en_US.UTF-8`.

use std::ffi::{CStr, c_char, c_int};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *mut c_char;
type SnprintfFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, ...) -> c_int;

fn host_setlocale() -> SetlocaleFn {
    // SAFETY: `char *setlocale(int, const char *)`; fl's export is passed so a
    // collapsed oracle aborts rather than comparing fl with itself.
    unsafe {
        host_fn(
            c"setlocale",
            frankenlibc_abi::locale_abi::setlocale as *const (),
        )
    }
}

fn host_snprintf() -> SnprintfFn {
    // SAFETY: `int snprintf(char *, size_t, const char *, ...)`.
    unsafe {
        host_fn(
            c"snprintf",
            frankenlibc_abi::stdio_abi::snprintf as *const (),
        )
    }
}

fn render(f: SnprintfFn, fmt: &CStr, arg: Arg) -> String {
    let mut buf = [0 as c_char; 256];
    // SAFETY: 256-byte buffer, size passed; one argument matching `fmt`.
    let n = unsafe {
        match arg {
            Arg::Int(v) => f(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), v),
            Arg::Long(v) => f(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), v),
            Arg::Double(v) => f(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), v),
        }
    };
    assert!(n >= 0, "{fmt:?} failed");
    // SAFETY: snprintf NUL-terminated the buffer.
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

#[derive(Clone, Copy)]
enum Arg {
    Int(c_int),
    Long(i64),
    Double(f64),
}

const CASES: &[(&CStr, Arg)] = &[
    (c"%'d", Arg::Int(1234567)),
    (c"%'d", Arg::Int(-2147483648)),
    (c"%'d", Arg::Int(999)),
    (c"%'i", Arg::Int(-1000)),
    (c"%'u", Arg::Int(-1000)),
    (c"%'ld", Arg::Long(i64::MAX)),
    (c"%'lld", Arg::Long(-123456789012)),
    (c"%'12d", Arg::Int(1234567)),
    (c"%'-12d|", Arg::Int(-1000)),
    (c"%'012d", Arg::Int(1000)),
    (c"%'012d", Arg::Int(-1000)),
    (c"%'+d", Arg::Int(12345)),
    (c"%' d", Arg::Int(12345)),
    (c"%'.8d", Arg::Int(1000)),
    (c"%'12.8d", Arg::Int(-123456)),
    (c"%'x", Arg::Int(-1000)),
    (c"%'#x", Arg::Int(12345)),
    (c"%'o", Arg::Int(1234567)),
    (c"%'f", Arg::Double(1234567.891)),
    (c"%'.2f", Arg::Double(-1234567.891)),
    (c"%'.0f", Arg::Double(999.5)),
    (c"%'#.0f", Arg::Double(123456.0)),
    (c"%'F", Arg::Double(1e22)),
    (c"%'g", Arg::Double(1000.25)),
    (c"%'.10g", Arg::Double(-1234567.891)),
    (c"%'g", Arg::Double(-1234567.891)),
    (c"%'e", Arg::Double(1234567.891)),
    (c"%'a", Arg::Double(1234567.891)),
    (c"%'15.2f", Arg::Double(1000.25)),
    (c"%'015.2f", Arg::Double(-1234567.891)),
    (c"%'-15.2f|", Arg::Double(123456.0)),
    (c"%'+.1f", Arg::Double(1000.25)),
    (c"%'f", Arg::Double(f64::INFINITY)),
    (c"%'.3f", Arg::Double(0.5)),
];

/// The radix without grouping: every float conversion prints LC_NUMERIC's
/// `decimal_point` (glibc: `%a` included).
const RADIX_CASES: &[(&CStr, Arg)] = &[
    (c"%f", Arg::Double(1.5)),
    (c"%.3e", Arg::Double(12345.678)),
    (c"%g", Arg::Double(0.25)),
    (c"%a", Arg::Double(1.5)),
    (c"%.0f", Arg::Double(2.0)),
    (c"%#.0f", Arg::Double(2.0)),
    (c"%10.2f|", Arg::Double(-3.25)),
    (c"%-10.2f|", Arg::Double(3.25)),
    (c"%010.2f", Arg::Double(-3.25)),
    (c"%f", Arg::Double(f64::NAN)),
];

/// Compile `locales` from the host's sources into a fresh LOCPATH, or say why
/// not.
fn compiled_locpath(locales: &[&str]) -> Result<std::path::PathBuf, String> {
    let dir = std::env::temp_dir().join(format!("fl_printf_locpath_{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {dir:?}: {e}"))?;
    for name in locales {
        let status = std::process::Command::new("localedef")
            .args(["-i", name, "-f", "UTF-8"])
            .arg(dir.join(format!("{name}.UTF-8")))
            .status()
            .map_err(|e| format!("localedef not runnable: {e}"))?;
        if !status.success() {
            return Err(format!("localedef -i {name} failed: {status}"));
        }
    }
    Ok(dir)
}

#[test]
fn printf_grouping_flag_matches_glibc_under_en_us_and_c() {
    let (host_set, host_snp) = (host_setlocale(), host_snprintf());
    let fl_snp: SnprintfFn = frankenlibc_abi::stdio_abi::snprintf;
    // SAFETY: valid category and NUL-terminated names.
    let host_ok = !unsafe { host_set(libc::LC_ALL, c"en_US.UTF-8".as_ptr()) }.is_null();
    if !host_ok {
        println!("SKIP: host has no en_US.UTF-8 locale (locale -a); nothing to compare");
        return;
    }
    // SAFETY: as above, fl's own setlocale.
    let fl_ok =
        !unsafe { frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, c"en_US.UTF-8".as_ptr()) }
            .is_null();
    assert!(
        fl_ok,
        "fl could not load en_US.UTF-8 although the host has it"
    );

    let mut grouped = 0usize;
    let mut bad = Vec::new();
    for &(fmt, arg) in CASES {
        let (h, m) = (render(host_snp, fmt, arg), render(fl_snp, fmt, arg));
        if h.contains(',') {
            grouped += 1;
        }
        if h != m {
            bad.push(format!("en_US {fmt:?}: glibc {h:?}, fl {m:?}"));
        }
    }

    // Back to C: the flag must group nothing, in both.
    // SAFETY: as above.
    unsafe {
        host_set(libc::LC_ALL, c"C".as_ptr());
        frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, c"C".as_ptr());
    }
    for &(fmt, arg) in CASES {
        let (h, m) = (render(host_snp, fmt, arg), render(fl_snp, fmt, arg));
        if h != m {
            bad.push(format!("C {fmt:?}: glibc {h:?}, fl {m:?}"));
        }
    }

    // Locales whose radix is ',' and whose separator is '.' (de_DE) or the
    // three-byte U+202F (fr_FR): the radix must be substituted before grouping,
    // and a float's width counts a multi-byte separator as one (glibc lays
    // floats out in wide characters).
    let mut radix_rows = 0usize;
    match compiled_locpath(&["de_DE", "fr_FR"]) {
        Err(why) => println!("SKIP de_DE/fr_FR: {why}"),
        Ok(locpath) => {
            // SAFETY: single test in this binary; no other thread reads the
            // environment concurrently.
            unsafe { std::env::set_var("LOCPATH", &locpath) };
            for name in [c"de_DE.UTF-8", c"fr_FR.UTF-8"] {
                // SAFETY: as above.
                let h = !unsafe { host_set(libc::LC_ALL, name.as_ptr()) }.is_null();
                // SAFETY: as above.
                let m =
                    !unsafe { frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, name.as_ptr()) }
                        .is_null();
                assert!(h && m, "{name:?} did not load: glibc {h}, fl {m}");
                for &(fmt, arg) in CASES.iter().chain(RADIX_CASES) {
                    let (h, m) = (render(host_snp, fmt, arg), render(fl_snp, fmt, arg));
                    if h.contains(',') && !h.contains('.') {
                        radix_rows += 1;
                    }
                    if h != m {
                        bad.push(format!("{name:?} {fmt:?}: glibc {h:?}, fl {m:?}"));
                    }
                }
            }
            // SAFETY: as above.
            unsafe {
                host_set(libc::LC_ALL, c"C".as_ptr());
                frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, c"C".as_ptr());
            }
        }
    }

    println!(
        "{} cases x 2 locales; {grouped} grouped under en_US; {radix_rows} ',' radix rows",
        CASES.len()
    );
    // Non-vacuity: without grouped rows this would pass with the flag ignored.
    assert!(grouped >= 20, "only {grouped} en_US cases grouped");
    assert!(
        bad.is_empty(),
        "{} divergent:\n  {}",
        bad.len(),
        bad.join("\n  ")
    );
}
