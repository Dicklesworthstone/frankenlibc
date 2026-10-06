#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strfmon oracle
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{CStr, CString, c_char, c_double};
unsafe extern "C" {
    fn strfmon(s: *mut c_char, max: usize, fmt: *const c_char, ...) -> isize;
    fn setlocale(cat: i32, loc: *const c_char) -> *mut c_char;
}
fn render(eng: u8, fmt: &CString, v: c_double) -> (isize, String) {
    let mut b = [0u8; 128];
    let n = if eng == 0 {
        unsafe { fl::strfmon(b.as_mut_ptr() as *mut c_char, 128, fmt.as_ptr(), v) }
    } else {
        unsafe { strfmon(b.as_mut_ptr() as *mut c_char, 128, fmt.as_ptr(), v) }
    };
    let s = if n < 0 {
        String::new()
    } else {
        unsafe { CStr::from_ptr(b.as_ptr() as *const c_char) }
            .to_string_lossy()
            .into_owned()
    };
    (n, s)
}
#[test]
fn strfmon_format_matrix_parity_vs_glibc() {
    // C locale (default). strfmon in C locale uses minimal formatting.
    unsafe {
        setlocale(6 /*LC_ALL*/, c"C".as_ptr());
    }
    let fmts = [
        "%n",
        "%i",
        "%.2n",
        "%.0n",
        "%#5n",
        "%#5.2n",
        "%=*#6n",
        "%^n",
        "%(n",
        "%!n",
        "%-14#5.4n",
        "%11.2n",
        "%.4i",
        "%+n",
        "%(#8n",
        "100%% of %n",
        "%15n|",
        "%-15n|",
    ];
    let vals: &[f64] = &[
        0.0,
        -0.0,
        1.0,
        -1.0,
        1234.567,
        -1234.567,
        0.005,
        -0.005,
        1000000.0,
        0.5,
        -0.5,
        99.995,
        0.001,
        123456789.99,
    ];
    let mut div = Vec::new();
    for fmt in fmts {
        let cf = match CString::new(fmt) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for &v in vals {
            let f = render(0, &cf, v);
            let g = render(1, &cf, v);
            if f != g {
                div.push(format!(
                    "strfmon({fmt:?}, {v}): fl=(ret {},{:?}) glibc=(ret {},{:?})",
                    f.0, f.1, g.0, g.1
                ));
            }
        }
    }
    if !div.is_empty() {
        eprintln!("STRFMON DIVERGENCES ({}):", div.len());
        for d in div.iter().take(80) {
            eprintln!("  {d}");
        }
    }
    assert!(div.is_empty(), "{} strfmon divergences", div.len());
}

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type StrfmonFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, ...) -> isize;
type ErrnoLocationFn = unsafe extern "C" fn() -> *mut i32;

/// `(return, errno if -1, bytes through the terminator if >= 0)` for one call
/// into a 0xA5-filled buffer one byte larger than `maxsize`, whose last byte
/// must survive. Two values are always passed; one-directive formats ignore
/// the second.
fn render_capped(host: bool, fmt: &CString, maxsize: usize, v: [f64; 2]) -> (isize, i32, Vec<u8>) {
    let mut b = vec![0xA5u8; maxsize + 1];
    let p = b.as_mut_ptr() as *mut c_char;
    // SAFETY: `b` holds `maxsize + 1` writable bytes, `fmt` is NUL-terminated,
    // and both entry points take `double` variadic arguments. The host arm and
    // its errno slot are resolved with dlsym, so they cannot bind to fl.
    let (n, err) = unsafe {
        if host {
            let f: StrfmonFn = dlsym_oracle::host_fn(c"strfmon", fl::strfmon as *const ());
            let errno: ErrnoLocationFn = dlsym_oracle::host_fn(
                c"__errno_location",
                frankenlibc_abi::errno_abi::__errno_location as *const (),
            );
            *errno() = 0;
            let n = f(p, maxsize, fmt.as_ptr(), v[0], v[1]);
            (n, *errno())
        } else {
            *frankenlibc_abi::errno_abi::__errno_location() = 0;
            let n = fl::strfmon(p, maxsize, fmt.as_ptr(), v[0], v[1]);
            (n, *frankenlibc_abi::errno_abi::__errno_location())
        }
    };
    assert_eq!(
        b[maxsize], 0xA5,
        "strfmon({fmt:?}) wrote past maxsize={maxsize}"
    );
    if n < 0 {
        (n, err, Vec::new())
    } else {
        (n, 0, b[..=n as usize].to_vec())
    }
}

/// The C-locale fast paths restored from merge `0be7b9dafe87` stream one or
/// more `%n`/`%i` directives (flags `^ ! + ( -`, a width, `.2`) and the literal
/// text between them straight into the caller's buffer, checking the capacity
/// per field. The matrix above only uses a 128-byte buffer and one value. This
/// gate drives single- and multi-directive fast-path formats with two values
/// at every capacity from 1 to the full length + 2, and compares the return
/// value, errno on failure, and the bytes on success against glibc.
///
/// Shapes the fast path must decline are compared once, in a 512-byte buffer
/// and with finite values: that proves the decline leaves the argument cursor
/// to the general parser. Two general-parser divergences are known and are not
/// this gate's subject: a non-finite value under an explicit `#` or `.` precision
/// (see `conformance_diff_strfmon_nan_flags`), and errno for a malformed format
/// in a buffer too small for its first conversion (glibc reports E2BIG before
/// it reaches the bad directive; fl validates first and reports EINVAL).
#[test]
fn strfmon_sequences_and_capacity_boundaries_match_glibc() {
    let loc = CString::new("C").unwrap();
    type SetlocaleFn = unsafe extern "C" fn(i32, *const c_char) -> *mut c_char;
    // SAFETY: LC_ALL with a NUL-terminated name, through each arm in turn.
    unsafe {
        let host_setlocale: SetlocaleFn = dlsym_oracle::host_fn(
            c"setlocale",
            frankenlibc_abi::locale_abi::setlocale as *const (),
        );
        host_setlocale(6, loc.as_ptr());
        frankenlibc_abi::locale_abi::setlocale(6, loc.as_ptr());
    }
    let fast = [
        // single directive
        "%n",
        "%i",
        "%.2n",
        "%16n",
        "%-16n",
        "%(n",
        "%^!+12i",
        // literals and sequences
        "x%nx",
        "%n %n",
        "%n%n",
        "%i|%-12n|",
        "%(n, %(n",
        "100%% %n%%%n",
        "a%^!10nb%.2ic",
    ];
    let declined = ["%n %#5n", "%n %=*8n", "%n %.3n", "%(+n %n", "%n %q", "%n %"];
    let vals = [
        0.0,
        -0.0,
        1234.567,
        -1234.567,
        0.005,
        -0.004,
        -9.995,
        1e15 + 0.125,
        f64::NAN,
        -f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ];
    let pairs: Vec<[f64; 2]> = (0..vals.len())
        .map(|k| [vals[k], vals[(k + 5) % vals.len()]])
        .collect();
    let mut div = Vec::new();
    let mut compared = 0usize;
    for fmt in fast {
        let cf = CString::new(fmt).unwrap();
        for &pair in &pairs {
            let (full, _, _) = render_capped(true, &cf, 512, pair);
            assert!(full > 0, "glibc rejected fast-path shape {fmt:?}");
            for maxsize in 1..=full as usize + 2 {
                let f = render_capped(false, &cf, maxsize, pair);
                let g = render_capped(true, &cf, maxsize, pair);
                compared += 1;
                if f != g {
                    div.push(format!(
                        "strfmon({fmt:?}, {pair:?}, maxsize={maxsize}): fl={f:?} glibc={g:?}"
                    ));
                    break;
                }
            }
        }
    }
    for fmt in declined {
        let cf = CString::new(fmt).unwrap();
        for &pair in pairs.iter().filter(|p| p.iter().all(|v| v.is_finite())) {
            let f = render_capped(false, &cf, 512, pair);
            let g = render_capped(true, &cf, 512, pair);
            compared += 1;
            if f != g {
                div.push(format!(
                    "strfmon({fmt:?}, {pair:?}, maxsize=512): fl={f:?} glibc={g:?}"
                ));
            }
        }
    }
    for d in div.iter().take(80) {
        eprintln!("  {d}");
    }
    assert!(compared > 1_000, "only {compared} comparisons ran");
    assert!(
        div.is_empty(),
        "{} strfmon capacity/sequence divergences, listed on stderr",
        div.len()
    );
}
