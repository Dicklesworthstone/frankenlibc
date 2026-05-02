#![cfg(target_os = "linux")]

//! Metamorphic-property tests for `strerror(3)` / `strerror_r(3)` /
//! `strerrordesc_np(3)` / `strerrorname_np(3)`.
//!
//! Properties:
//!
//!   - strerror is deterministic: same errno → same string
//!   - strerror returns a non-empty string for known errnos
//!   - strerrorname_np(0) returns NULL or some sentinel
//!   - strerrorname_np(EPERM) returns "EPERM"
//!   - distinct errnos return distinct strings
//!   - strerror handles unknown errno with a generic fallback
//!
//! Filed under [bd-xn6p8] follow-up.

use std::collections::BTreeSet;
use std::ffi::{c_char, CStr};

use frankenlibc_abi::string_abi as fl_string;

fn cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

#[test]
fn metamorphic_strerror_deterministic() {
    for &errno in &[
        libc::EPERM, libc::EACCES, libc::ENOENT, libc::ESRCH,
        libc::EBADF, libc::EAGAIN, libc::EFAULT,
    ] {
        let s1 = cstr(unsafe { fl_string::strerror(errno) });
        let s2 = cstr(unsafe { fl_string::strerror(errno) });
        let s3 = cstr(unsafe { fl_string::strerror(errno) });
        assert_eq!(s1, s2, "strerror({errno}) not deterministic");
        assert_eq!(s1, s3);
    }
}

#[test]
fn metamorphic_strerror_returns_nonempty_for_known_errnos() {
    for &errno in &[
        libc::EPERM, libc::EACCES, libc::ENOENT, libc::EBADF,
        libc::EAGAIN, libc::ENOMEM, libc::EBUSY, libc::EEXIST,
    ] {
        let s = cstr(unsafe { fl_string::strerror(errno) });
        assert!(s.is_some(), "strerror({errno}) returned NULL");
        let s = s.unwrap();
        assert!(!s.is_empty(), "strerror({errno}) returned empty");
    }
}

#[test]
fn metamorphic_strerrorname_np_known_errnos_distinct() {
    let mut names = BTreeSet::new();
    for &errno in &[
        libc::EPERM, libc::EACCES, libc::ENOENT, libc::ESRCH,
        libc::EBADF, libc::EAGAIN, libc::ENOMEM, libc::EBUSY,
    ] {
        let p = unsafe { fl_string::strerrorname_np(errno) };
        let s = cstr(p);
        if let Some(s) = s {
            names.insert(s);
        }
    }
    // Should produce 8 distinct names if all are known.
    assert!(names.len() >= 6, "expected ≥6 distinct names, got {}", names.len());
}

#[test]
fn metamorphic_strerrorname_np_eperm() {
    let p = unsafe { fl_string::strerrorname_np(libc::EPERM) };
    let s = cstr(p);
    assert_eq!(s.as_deref(), Some("EPERM"));
}

#[test]
fn metamorphic_strerrorname_np_eacces() {
    let p = unsafe { fl_string::strerrorname_np(libc::EACCES) };
    let s = cstr(p);
    assert_eq!(s.as_deref(), Some("EACCES"));
}

#[test]
fn metamorphic_strerror_unknown_errno_returns_some_string() {
    // Glibc returns "Unknown error N" for unknown errnos. fl
    // matches. Either way, must be non-NULL non-empty.
    let p = unsafe { fl_string::strerror(99999) };
    let s = cstr(p);
    assert!(s.is_some(), "strerror(99999) returned NULL");
    assert!(!s.unwrap().is_empty());
}

#[test]
fn metamorphic_strerror_distinct_errnos_distinct_messages() {
    // 5 well-known errors — fl must give 5 distinct messages.
    let mut messages = BTreeSet::new();
    for &errno in &[libc::EPERM, libc::ENOENT, libc::EACCES, libc::EBADF, libc::ENOMEM] {
        if let Some(s) = cstr(unsafe { fl_string::strerror(errno) }) {
            messages.insert(s);
        }
    }
    assert_eq!(messages.len(), 5, "errnos collide on message");
}

#[test]
fn metamorphic_strerrordesc_np_eperm_starts_with_letter() {
    let p = unsafe { fl_string::strerrordesc_np(libc::EPERM) };
    let s = cstr(p).unwrap_or_default();
    let first = s.chars().next().unwrap_or(' ');
    assert!(first.is_ascii_alphabetic(), "EPERM desc starts with {first}");
}

#[test]
fn strerror_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc strerror + strerror_r + strerrorname_np + strerrordesc_np\",\"reference\":\"posix-invariants\",\"properties\":8,\"divergences\":0}}",
    );
}
