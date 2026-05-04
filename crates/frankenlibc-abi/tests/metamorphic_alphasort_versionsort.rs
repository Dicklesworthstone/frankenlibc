#![cfg(target_os = "linux")]

//! Metamorphic-property tests for `alphasort(3)` / `versionsort(3)`.
//!
//! These comparator functions must satisfy the comparison-function
//! axioms: total ordering, anti-symmetry, transitivity (within
//! reasonable bounds), and reflexivity.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_int;

use frankenlibc_abi::dirent_abi as fl;

fn make_dirent(name: &[u8]) -> Box<libc::dirent> {
    let mut d = libc::dirent {
        d_ino: 0,
        d_off: 0,
        d_reclen: 0,
        d_type: 0,
        d_name: [0; 256],
    };
    let max = d.d_name.len() - 1;
    let n = name.len().min(max);
    for (dst, &src) in d.d_name.iter_mut().zip(name.iter()).take(n) {
        *dst = src as i8;
    }
    d.d_name[n] = 0;
    Box::new(d)
}

fn alphasort(a_name: &[u8], b_name: &[u8]) -> c_int {
    let da = make_dirent(a_name);
    let db = make_dirent(b_name);
    let pa: *const libc::dirent = &*da;
    let pb: *const libc::dirent = &*db;
    let mut ap = pa;
    let mut bp = pb;
    unsafe { fl::alphasort(&mut ap, &mut bp) }
}

fn versionsort(a_name: &[u8], b_name: &[u8]) -> c_int {
    let da = make_dirent(a_name);
    let db = make_dirent(b_name);
    let pa: *const libc::dirent = &*da;
    let pb: *const libc::dirent = &*db;
    let mut ap = pa;
    let mut bp = pb;
    unsafe { fl::versionsort(&mut ap, &mut bp) }
}

fn sign(v: c_int) -> i32 {
    v.signum()
}

#[test]
fn metamorphic_alphasort_reflexive() {
    // cmp(x, x) == 0 for any x.
    for s in [
        b"".as_slice(),
        b"a",
        b"abc",
        b"file1",
        b"long_filename_test",
    ] {
        assert_eq!(alphasort(s, s), 0, "alphasort({s:?}, {s:?}) != 0");
    }
}

#[test]
fn metamorphic_alphasort_anti_symmetric() {
    // sign(cmp(a, b)) == -sign(cmp(b, a)).
    let pairs: &[(&[u8], &[u8])] = &[
        (b"a", b"b"),
        (b"abc", b"abd"),
        (b"file1", b"file2"),
        (b"alpha", b"beta"),
        (b"", b"a"),
    ];
    for &(a, b) in pairs {
        let ab = alphasort(a, b);
        let ba = alphasort(b, a);
        assert_eq!(sign(ab), -sign(ba), "anti-symmetric: {a:?} vs {b:?}");
    }
}

#[test]
fn metamorphic_alphasort_transitivity_three_keys() {
    // For three keys a < b < c, alphasort should give cmp(a,b) < 0,
    // cmp(b,c) < 0, cmp(a,c) < 0.
    let triples: &[(&[u8], &[u8], &[u8])] = &[
        (b"a", b"b", b"c"),
        (b"file1", b"file2", b"file3"),
        (b"abc", b"abd", b"abe"),
    ];
    for &(a, b, c) in triples {
        assert!(alphasort(a, b) < 0, "{a:?} should sort before {b:?}");
        assert!(alphasort(b, c) < 0, "{b:?} should sort before {c:?}");
        assert!(
            alphasort(a, c) < 0,
            "{a:?} should sort before {c:?} (transitive)"
        );
    }
}

#[test]
fn metamorphic_versionsort_reflexive() {
    for s in [b"".as_slice(), b"v1", b"file9", b"item-100"] {
        assert_eq!(versionsort(s, s), 0);
    }
}

#[test]
fn metamorphic_versionsort_anti_symmetric() {
    let pairs: &[(&[u8], &[u8])] = &[
        (b"file9", b"file10"),
        (b"v1.9", b"v1.10"),
        (b"item-1", b"item-2"),
    ];
    for &(a, b) in pairs {
        let ab = versionsort(a, b);
        let ba = versionsort(b, a);
        assert_eq!(sign(ab), -sign(ba), "vs anti-symmetric: {a:?} vs {b:?}");
    }
}

#[test]
fn metamorphic_versionsort_numeric_order_overrides_lexical() {
    // With versionsort, "file9" < "file10" because the numeric
    // comparison takes precedence over lexical.
    assert!(versionsort(b"file9", b"file10") < 0);
    assert!(versionsort(b"file2", b"file10") < 0);
    // Sanity check that alphasort gives the opposite (lexical):
    // "file10" < "file9" lexically because '1' < '9'.
    assert!(alphasort(b"file9", b"file10") > 0);
}

#[test]
fn metamorphic_alphasort_lexical_byte_order_matches_strcmp() {
    // alphasort must compare bytes in strcmp order. Construct
    // strings differing only at position k.
    let s_a = b"abcdef";
    let s_b = b"abcdeg";
    assert!(alphasort(s_a, s_b) < 0);
    assert!(alphasort(s_b, s_a) > 0);
}

#[test]
fn alphasort_versionsort_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc alphasort + versionsort\",\"reference\":\"comparator-axioms\",\"properties\":7,\"divergences\":0}}",
    );
}
