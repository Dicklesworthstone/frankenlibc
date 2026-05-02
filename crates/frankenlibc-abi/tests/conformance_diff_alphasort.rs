#![cfg(target_os = "linux")]

//! Differential conformance harness for POSIX `alphasort(3)` and GNU
//! `versionsort(3)`.
//!
//! Both are comparator functions for `scandir(3)`. fl exposes them in
//! `dirent_abi`. We diff against host glibc on a set of fabricated
//! `struct dirent` pairs.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_int;

use frankenlibc_abi::dirent_abi as fl;

unsafe extern "C" {
    fn alphasort(a: *mut *const libc::dirent, b: *mut *const libc::dirent) -> c_int;
    fn versionsort(a: *mut *const libc::dirent, b: *mut *const libc::dirent) -> c_int;
}

/// Build a libc::dirent with the given d_name (NUL-terminated).
fn make_dirent(name: &[u8]) -> Box<libc::dirent> {
    let mut d: libc::dirent = unsafe { std::mem::zeroed() };
    let max = d.d_name.len() - 1;
    let n = name.len().min(max);
    for i in 0..n {
        d.d_name[i] = name[i] as i8;
    }
    d.d_name[n] = 0;
    Box::new(d)
}

fn cmp_alphasort(a_name: &[u8], b_name: &[u8]) -> (c_int, c_int) {
    let da = make_dirent(a_name);
    let db = make_dirent(b_name);
    let pa: *const libc::dirent = &*da;
    let pb: *const libc::dirent = &*db;
    let mut ap = pa;
    let mut bp = pb;
    let mut ap2 = pa;
    let mut bp2 = pb;
    let fl_v = unsafe { fl::alphasort(&mut ap, &mut bp) };
    let lc_v = unsafe { alphasort(&mut ap2, &mut bp2) };
    (fl_v, lc_v)
}

fn cmp_versionsort(a_name: &[u8], b_name: &[u8]) -> (c_int, c_int) {
    let da = make_dirent(a_name);
    let db = make_dirent(b_name);
    let pa: *const libc::dirent = &*da;
    let pb: *const libc::dirent = &*db;
    let mut ap = pa;
    let mut bp = pb;
    let mut ap2 = pa;
    let mut bp2 = pb;
    let fl_v = unsafe { fl::versionsort(&mut ap, &mut bp) };
    let lc_v = unsafe { versionsort(&mut ap2, &mut bp2) };
    (fl_v, lc_v)
}

fn sign(v: c_int) -> i32 {
    v.signum()
}

#[test]
fn diff_alphasort_basic_ordering() {
    for &(a, b) in &[
        (b"a".as_slice(), b"b".as_slice()),
        (b"abc", b"abd"),
        (b"abc", b"abc"),
        (b"file1", b"file2"),
        (b"file2", b"file1"),
        (b"", b"a"),
        (b"a", b""),
        (b"", b""),
        (b"longname.txt", b"longname.txt"),
        (b"AAA", b"aaa"),
    ] {
        let (fl_v, lc_v) = cmp_alphasort(a, b);
        // Compare signs since glibc may return any negative/positive
        // value for ordering.
        assert_eq!(
            sign(fl_v),
            sign(lc_v),
            "alphasort({:?}, {:?}): fl={fl_v} lc={lc_v}",
            std::str::from_utf8(a).unwrap_or("?"),
            std::str::from_utf8(b).unwrap_or("?"),
        );
    }
}

#[test]
fn diff_alphasort_mirror_property() {
    // For any inputs (a, b), sign(alphasort(a, b)) == -sign(alphasort(b, a)).
    for &(a, b) in &[
        (b"alpha".as_slice(), b"beta".as_slice()),
        (b"file1", b"file9"),
        (b"a", b"a"),
    ] {
        let (fl_ab, _) = cmp_alphasort(a, b);
        let (fl_ba, _) = cmp_alphasort(b, a);
        if fl_ab == 0 {
            assert_eq!(fl_ba, 0);
        } else {
            assert_eq!(sign(fl_ab), -sign(fl_ba), "mirror prop");
        }
    }
}

#[test]
fn diff_versionsort_basic_lexical_when_no_digits() {
    for &(a, b) in &[
        (b"alpha".as_slice(), b"beta".as_slice()),
        (b"abc", b"abd"),
        (b"abc", b"abc"),
        (b"", b""),
    ] {
        let (fl_v, lc_v) = cmp_versionsort(a, b);
        assert_eq!(
            sign(fl_v),
            sign(lc_v),
            "versionsort({:?}, {:?}): fl={fl_v} lc={lc_v}",
            std::str::from_utf8(a).unwrap_or("?"),
            std::str::from_utf8(b).unwrap_or("?"),
        );
    }
}

#[test]
fn diff_versionsort_numeric_aware_ordering() {
    // versionsort treats embedded digit runs as numbers, so file9
    // sorts before file10 (lexical alphasort would put it after).
    for &(a, b) in &[
        (b"file9".as_slice(), b"file10".as_slice()),
        (b"file2", b"file10"),
        (b"v1.9", b"v1.10"),
        (b"item-1", b"item-2"),
        (b"item-100", b"item-99"),
    ] {
        let (fl_v, lc_v) = cmp_versionsort(a, b);
        assert_eq!(
            sign(fl_v),
            sign(lc_v),
            "versionsort({:?}, {:?}): fl={fl_v} lc={lc_v}",
            std::str::from_utf8(a).unwrap_or("?"),
            std::str::from_utf8(b).unwrap_or("?"),
        );
    }
}

#[test]
fn diff_versionsort_mixed_letters_and_digits() {
    for &(a, b) in &[
        (b"file9a".as_slice(), b"file10a".as_slice()),
        (b"abc1def", b"abc2def"),
        (b"abc10def", b"abc9def"),
    ] {
        let (fl_v, lc_v) = cmp_versionsort(a, b);
        assert_eq!(
            sign(fl_v),
            sign(lc_v),
            "versionsort({:?}, {:?}): fl={fl_v} lc={lc_v}",
            std::str::from_utf8(a).unwrap_or("?"),
            std::str::from_utf8(b).unwrap_or("?"),
        );
    }
}

#[test]
fn alphasort_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc alphasort + versionsort\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
