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

use std::os::raw::{c_char, c_int};

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::stdlib_abi::confstr;

fn fl_errno() -> c_int {
    unsafe { *__errno_location() }
}

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

#[test]
fn confstr_unsupported_keys_return_zero_einval() {
    // Keys outside the supported set must return 0 and set EINVAL (glibc behavior).
    for key in [6, 7, 100, 999, 1008, 1099, 1150, 2000, -1] {
        let (n, _) = fl_confstr(key);
        assert_eq!(n, 0, "confstr({key}) should be unsupported (return 0)");
        assert_eq!(
            fl_errno(),
            libc::EINVAL,
            "confstr({key}) unsupported should set EINVAL"
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
    }
}
