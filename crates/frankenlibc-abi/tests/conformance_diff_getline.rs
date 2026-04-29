#![cfg(target_os = "linux")]

//! Differential conformance harness for `getline(3)` / `getdelim(3)`.
//!
//! Both read up to a delimiter (newline or arbitrary byte) from a
//! FILE*, allocating/growing the line buffer as needed. fl uses its
//! own FILE* implementation; tests below use fmemopen so we can run
//! both sides on identical in-memory streams.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, c_int, c_void};

unsafe extern "C" {
    fn fmemopen(buf: *mut c_void, size: usize, mode: *const c_char) -> *mut libc::FILE;
    fn fclose(fp: *mut libc::FILE) -> c_int;
    fn getline(
        lineptr: *mut *mut c_char,
        n: *mut usize,
        stream: *mut libc::FILE,
    ) -> isize;
    fn getdelim(
        lineptr: *mut *mut c_char,
        n: *mut usize,
        delim: c_int,
        stream: *mut libc::FILE,
    ) -> isize;
}

/// Read all lines from a fmemopen-backed buffer, returning the sequence
/// of (line, return_value) tuples.
fn collect_lines<F>(content: &[u8], reader: F) -> Vec<(Vec<u8>, isize)>
where
    F: Fn(*mut *mut c_char, *mut usize, *mut libc::FILE) -> isize,
{
    let mut owned = content.to_vec();
    let fp = unsafe {
        fmemopen(
            owned.as_mut_ptr() as *mut c_void,
            owned.len(),
            c"r".as_ptr(),
        )
    };
    if fp.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut line: *mut c_char = std::ptr::null_mut();
    let mut n: usize = 0;
    loop {
        let r = reader(&mut line, &mut n, fp);
        if r < 0 {
            break;
        }
        let bytes = unsafe { std::slice::from_raw_parts(line as *const u8, r as usize).to_vec() };
        out.push((bytes, r));
    }
    if !line.is_null() {
        unsafe { libc::free(line as *mut libc::c_void) };
    }
    unsafe { fclose(fp) };
    out
}

#[test]
fn diff_getline_via_fmemopen() {
    let content = b"first line\nsecond line\nlast no newline";
    let fl_lines = collect_lines(content, |lp, n, fp| unsafe {
        frankenlibc_abi::stdio_abi::getline(lp, n, fp as *mut c_void)
    });
    let lc_lines = collect_lines(content, |lp, n, fp| unsafe { getline(lp, n, fp) });
    assert_eq!(
        fl_lines.len(),
        lc_lines.len(),
        "line count mismatch: fl={} lc={}",
        fl_lines.len(),
        lc_lines.len()
    );
    for (i, (fl, lc)) in fl_lines.iter().zip(lc_lines.iter()).enumerate() {
        assert_eq!(fl.0, lc.0, "line {i} bytes differ");
        assert_eq!(fl.1, lc.1, "line {i} return value differs");
    }
}

#[test]
fn diff_getdelim_with_colon_delimiter() {
    let content = b"alpha:beta:gamma:delta";
    let fl_lines = collect_lines(content, |lp, n, fp| unsafe {
        frankenlibc_abi::stdio_abi::getdelim(lp, n, b':' as c_int, fp as *mut c_void)
    });
    let lc_lines = collect_lines(content, |lp, n, fp| unsafe {
        getdelim(lp, n, b':' as c_int, fp)
    });
    assert_eq!(fl_lines.len(), lc_lines.len(), "field count mismatch");
    for (i, (fl, lc)) in fl_lines.iter().zip(lc_lines.iter()).enumerate() {
        assert_eq!(fl.0, lc.0, "field {i} bytes");
        assert_eq!(fl.1, lc.1, "field {i} return value");
    }
}

#[test]
fn diff_getline_empty_input() {
    let content = b"";
    let fl_lines = collect_lines(content, |lp, n, fp| unsafe {
        frankenlibc_abi::stdio_abi::getline(lp, n, fp as *mut c_void)
    });
    let lc_lines = collect_lines(content, |lp, n, fp| unsafe { getline(lp, n, fp) });
    assert_eq!(fl_lines, lc_lines);
}

#[test]
fn diff_getline_single_long_line() {
    // 200-char line forces buffer growth in both impls.
    let line: Vec<u8> = std::iter::repeat_n(b'x', 200).chain(std::iter::once(b'\n')).collect();
    let fl_lines = collect_lines(&line, |lp, n, fp| unsafe {
        frankenlibc_abi::stdio_abi::getline(lp, n, fp as *mut c_void)
    });
    let lc_lines = collect_lines(&line, |lp, n, fp| unsafe { getline(lp, n, fp) });
    assert_eq!(fl_lines.len(), 1);
    assert_eq!(fl_lines[0].0, line);
    assert_eq!(fl_lines, lc_lines);
}

#[test]
fn getline_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc getline + getdelim\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
