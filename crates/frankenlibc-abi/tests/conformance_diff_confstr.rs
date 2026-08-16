//! Differential conformance gate for `confstr(3)`.
//!
//! frankenlibc historically answered only 3 `_CS_*` keys (_CS_PATH,
//! _CS_GNU_LIBC_VERSION, _CS_GNU_LIBPTHREAD_VERSION) and returned 0 + EINVAL for
//! everything else. Host glibc on x86_64 (LP64) supports 64 keys: the
//! width-restricted-env names (0,1,4,5), the version strings (2,3), the LFS /
//! LFS64 flag set (1000..=1007), and the POSIX_V6/V7 programming-environment +
//! ENV strings (1100..=1149).
//!
//! The expected values below were captured by a `confstr(0..1300, ...)`
//! brute-probe of host glibc; they are x86_64 LP64 platform constants. Keys 2/3
//! intentionally report frankenlibc's declared compat level ("2.38"), so this
//! gate pins them to the frankenlibc value rather than the live host version.
//!
//! confstr's contract: returns the length of the value INCLUDING the trailing
//! NUL. A supported-but-empty key returns 1 (just the NUL); an unsupported key
//! returns 0 and sets errno to EINVAL.
//!
//! ## Live arm added 2026-08-16 (bd-v0388t)
//!
//! This gate had NO host arm: its test was named `confstr_matches_glibc_x86_64_lp64`
//! and it compared fl against a table of literals, so the parity in the name was
//! never measured. That is the worst shape here of all the frozen-golden gates,
//! because what confstr returns is a HOST property by definition — the values
//! were brute-probed off one glibc on one machine, and both the library and the
//! platform are free to move underneath them. Keys 2 and 3 are literally a
//! version string.
//!
//! The goldens are KEPT — they record what the implementation intended — and a
//! dlsym-resolved arm is added on the same keys. A divergence now names which
//! side moved: fl regressing fails the golden assertion, the host differing
//! fails the differential one.
//!
//! Keys 2/3 (`_CS_GNU_LIBC_VERSION`, `_CS_GNU_LIBPTHREAD_VERSION`) are the one
//! deliberate non-parity: fl reports its declared compat level ("glibc 2.38")
//! rather than the running host's. They are excluded from the value comparison
//! and checked for SHAPE instead, so the exclusion cannot quietly widen into
//! "this key is not tested".

use std::os::raw::{c_char, c_int};

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::stdlib_abi::confstr;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type ConfstrFn = unsafe extern "C" fn(c_int, *mut c_char, usize) -> usize;
type ErrnoLocationFn = unsafe extern "C" fn() -> *mut c_int;

fn host_confstr_fn() -> ConfstrFn {
    // SAFETY: signature matches C's confstr exactly.
    unsafe {
        dlsym_oracle::host_fn(
            c"confstr",
            frankenlibc_abi::stdlib_abi::confstr as *const (),
        )
    }
}

/// glibc's errno slot, which is NOT fl's.
///
/// The two implementations keep separate errno storage, so reading fl's location
/// after calling the host arm would report whatever fl last set — a comparison
/// of one implementation against itself, in the exact place (an unsupported key
/// sets EINVAL and returns 0) where errno is the only thing that differs.
fn host_errno_fn() -> ErrnoLocationFn {
    // SAFETY: signature matches C's __errno_location exactly.
    unsafe {
        dlsym_oracle::host_fn(
            c"__errno_location",
            frankenlibc_abi::errno_abi::__errno_location as *const (),
        )
    }
}

fn fl_errno() -> c_int {
    unsafe { *__errno_location() }
}

/// Call host glibc's confstr with the same generous buffer fl gets.
fn host_confstr(name: c_int) -> (usize, Vec<u8>) {
    let f = host_confstr_fn();
    let errno_loc = host_errno_fn();
    let mut buf = vec![0u8; 512];
    // SAFETY: buf is 512 writable bytes and the length passed matches it.
    unsafe {
        *errno_loc() = 0;
        let n = f(name, buf.as_mut_ptr() as *mut c_char, buf.len());
        let s: Vec<u8> = buf.iter().copied().take_while(|&b| b != 0).collect();
        (n, s)
    }
}

fn host_errno() -> c_int {
    // SAFETY: the resolved location is glibc's per-thread errno slot.
    unsafe { *host_errno_fn()() }
}

/// Keys where fl reports its own compat level rather than the running host's.
const VERSION_KEYS: [c_int; 2] = [2, 3];

/// Call frankenlibc confstr with a generous buffer; return (ret_len, string_bytes).
fn fl_confstr(name: c_int) -> (usize, Vec<u8>) {
    let mut buf = vec![0u8; 512];
    unsafe {
        *__errno_location() = 0;
        let n = confstr(name, buf.as_mut_ptr() as *mut c_char, buf.len());
        // String content = bytes up to the first NUL (confstr always NUL-terminates).
        let s: Vec<u8> = buf.iter().copied().take_while(|&b| b != 0).collect();
        (n, s)
    }
}

/// Golden table: (key, expected_return_len_including_nul, expected_string).
fn golden() -> Vec<(c_int, usize, &'static str)> {
    let mut v: Vec<(c_int, usize, &'static str)> = vec![
        (0, 14, "/bin:/usr/bin"),
        (1, 20, "POSIX_V6_LP64_OFF64"),
        (2, 11, "glibc 2.38"),
        (3, 10, "NPTL 2.38"),
        (4, 16, "XBS5_LP64_OFF64"),
        (5, 20, "POSIX_V7_LP64_OFF64"),
        (1148, 18, "POSIXLY_CORRECT=1"),
        (1149, 18, "POSIXLY_CORRECT=1"),
    ];
    // LFS / LFS64 block: 1000..=1007. Only LFS64 CFLAGS(1004)/LINTFLAGS(1007) carry a flag.
    for k in 1000..=1007 {
        if k == 1004 || k == 1007 {
            v.push((k, 22, "-D_LARGEFILE64_SOURCE"));
        } else {
            v.push((k, 1, ""));
        }
    }
    // POSIX_V6/V7 environment flags: 1100..=1147. Only the LP64_OFF64
    // CFLAGS/LDFLAGS (1108/1109, 1124/1125, 1140/1141) carry "-m64".
    for k in 1100..=1147 {
        if matches!(k, 1108 | 1109 | 1124 | 1125 | 1140 | 1141) {
            v.push((k, 5, "-m64"));
        } else {
            v.push((k, 1, ""));
        }
    }
    v
}

#[test]
fn confstr_matches_glibc_x86_64_lp64() {
    let mut mismatches = Vec::new();
    for (key, exp_len, exp_str) in golden() {
        let (got_len, got_str) = fl_confstr(key);
        let got_str_s = String::from_utf8_lossy(&got_str);
        if got_len != exp_len || got_str_s != exp_str {
            mismatches.push(format!(
                "key {key}: got (len={got_len}, str={got_str_s:?}), want (len={exp_len}, str={exp_str:?})"
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "confstr diverged from glibc on {} key(s):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// The same keys, against the glibc that is actually running.
///
/// Kept separate from the golden test on purpose: when this one is red and that
/// one is green, the host moved, not fl — which is a different piece of news and
/// a different fix.
#[test]
fn confstr_matches_live_glibc_on_the_same_keys() {
    let mut mismatches = Vec::new();
    let mut compared = 0usize;
    for (key, _, _) in golden() {
        let (fl_len, fl_str) = fl_confstr(key);
        let (gl_len, gl_str) = host_confstr(key);
        if VERSION_KEYS.contains(&key) {
            continue;
        }
        compared += 1;
        if (fl_len, &fl_str) != (gl_len, &gl_str) {
            mismatches.push(format!(
                "key {key}: fl (len={fl_len}, str={:?}) vs live glibc (len={gl_len}, str={:?})",
                String::from_utf8_lossy(&fl_str),
                String::from_utf8_lossy(&gl_str)
            ));
        }
    }
    // A zero mismatch count is only evidence if the loop did work.
    assert_eq!(
        compared,
        golden().len() - VERSION_KEYS.len(),
        "not every golden key reached the live arm"
    );
    assert!(
        mismatches.is_empty(),
        "fl's confstr diverges from the running glibc on {} of {compared} key(s):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// The two keys fl answers from its own compat level rather than from the host.
///
/// Excluded from the comparison above, so they are checked here instead — an
/// exclusion with no assertion behind it is how a key stops being tested at all.
#[test]
fn version_keys_are_a_deliberate_non_parity_with_the_right_shape() {
    for (key, prefix) in [(2, "glibc "), (3, "NPTL ")] {
        let (fl_len, fl_str) = fl_confstr(key);
        let (gl_len, gl_str) = host_confstr(key);
        let fl_s = String::from_utf8_lossy(&fl_str).into_owned();
        let gl_s = String::from_utf8_lossy(&gl_str).into_owned();

        assert!(
            fl_s.starts_with(prefix),
            "fl confstr({key}) = {fl_s:?}, expected to start with {prefix:?}"
        );
        assert!(
            gl_s.starts_with(prefix),
            "live glibc confstr({key}) = {gl_s:?}, expected to start with {prefix:?}"
        );
        assert_eq!(fl_len, fl_s.len() + 1, "fl length includes the NUL");
        assert_eq!(gl_len, gl_s.len() + 1, "glibc length includes the NUL");
        println!("confstr({key}): fl {fl_s:?} vs live glibc {gl_s:?} (declared non-parity)");
    }
}

#[test]
fn confstr_unsupported_keys_return_zero_einval() {
    // Keys outside the supported set must return 0 and set EINVAL (glibc behavior).
    // The live arm is asserted on the same keys because "unsupported" is a claim
    // about the host: a key glibc has since started answering would otherwise
    // show up as nothing at all, which is the failure mode with no symptom.
    for key in [6, 7, 100, 999, 1008, 1099, 1150, 2000, -1] {
        let (n, _) = fl_confstr(key);
        assert_eq!(n, 0, "confstr({key}) should be unsupported (return 0)");
        assert_eq!(
            fl_errno(),
            libc::EINVAL,
            "confstr({key}) unsupported should set EINVAL"
        );

        let (gn, _) = host_confstr(key);
        assert_eq!(gn, 0, "live glibc confstr({key}) should be unsupported too");
        assert_eq!(
            host_errno(),
            libc::EINVAL,
            "live glibc confstr({key}) unsupported should set EINVAL"
        );
    }
}

#[test]
fn confstr_length_query_with_null_buffer() {
    // confstr(name, NULL, 0) returns the required length without writing.
    let (full_len, _) = fl_confstr(0);
    unsafe {
        let n = confstr(0, std::ptr::null_mut(), 0);
        assert_eq!(n, full_len, "_CS_PATH length query via NULL buffer");
        // SAFETY: NULL/0 is the documented length-query form.
        let gn = host_confstr_fn()(0, std::ptr::null_mut(), 0);
        assert_eq!(gn, n, "_CS_PATH NULL-buffer length query: fl vs live glibc");
    }
}

#[test]
fn confstr_truncation_nul_terminates() {
    // With a too-small buffer, confstr returns the FULL length but writes a
    // NUL-terminated truncation.
    let mut buf = [0xAAu8; 8];
    unsafe {
        let n = confstr(0, buf.as_mut_ptr() as *mut c_char, buf.len());
        assert_eq!(n, 14, "_CS_PATH full length even when truncated");
        // Last byte of the provided buffer must be NUL.
        assert_eq!(buf[7], 0, "truncated confstr output must be NUL-terminated");
        let s: Vec<u8> = buf.iter().copied().take_while(|&b| b != 0).collect();
        assert_eq!(&s, b"/bin:/u", "truncated _CS_PATH prefix");

        // Same 8-byte buffer through the host arm: the truncation rule is the
        // part a caller sizing a buffer depends on.
        let mut gbuf = [0xAAu8; 8];
        // SAFETY: gbuf is 8 writable bytes and the length passed matches it.
        let gn = host_confstr_fn()(0, gbuf.as_mut_ptr() as *mut c_char, gbuf.len());
        assert_eq!(gn, n, "truncated _CS_PATH full length: fl vs live glibc");
        assert_eq!(
            gbuf, buf,
            "truncated _CS_PATH bytes: fl vs live glibc (buffer written, including the NUL)"
        );
    }
}

/// The oracle arm is glibc's, not fl's.
///
/// `host_fn` already asserts this on every resolution, but stating it as its own
/// test means a future edit that drops the live arm fails here rather than
/// leaving the file quietly back where it started.
#[test]
fn the_host_arm_is_not_fl() {
    let resolved = unsafe {
        dlsym_oracle::host_addr(c"confstr", frankenlibc_abi::stdlib_abi::confstr as *const ())
    };
    assert_ne!(
        resolved as usize,
        frankenlibc_abi::stdlib_abi::confstr as *const () as usize,
        "the resolved confstr oracle is fl's own definition"
    );
}
