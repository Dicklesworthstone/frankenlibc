#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc pthread_rwlockattr oracle

//! `pthread_rwlockattr_setkind_np`/`getkind_np` round-trip parity (bd-cykuni).
//!
//! glibc stores the reader/writer-preference kind in the attribute object, so
//! `setkind_np(attr, k); getkind_np(attr, &g)` yields `g == k`. fl previously
//! discarded the value in setkind_np and always returned 0 from getkind_np.
//! This gate pins fl's round-trip against glibc for every valid kind, that the
//! kind survives a `setpshared` change, and that getpshared/getkind stay
//! independent. fl uses its own attribute encoding (the object is opaque, only
//! touched through these calls), so we compare fl-to-fl round-trip and
//! fl-to-glibc agreement on the observable kind, not the raw bytes.

use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn pthread_rwlockattr_init(attr: *mut c_void) -> c_int;
    fn pthread_rwlockattr_setkind_np(attr: *mut c_void, kind: c_int) -> c_int;
    fn pthread_rwlockattr_getkind_np(attr: *const c_void, kind: *mut c_int) -> c_int;
    fn pthread_rwlockattr_setpshared(attr: *mut c_void, pshared: c_int) -> c_int;
    fn pthread_rwlockattr_getpshared(attr: *const c_void, pshared: *mut c_int) -> c_int;
}

// fl entry points (Rust-visible; not no_mangle in test builds).
use frankenlibc_abi::glibc_internal_abi::{
    pthread_rwlockattr_getkind_np as fl_getkind, pthread_rwlockattr_setkind_np as fl_setkind,
};
use frankenlibc_abi::pthread_abi::{
    pthread_rwlockattr_getpshared as fl_getpshared, pthread_rwlockattr_init as fl_init,
    pthread_rwlockattr_setpshared as fl_setpshared,
};

const KINDS: [c_int; 3] = [
    0, // PTHREAD_RWLOCK_PREFER_READER_NP
    1, // PTHREAD_RWLOCK_PREFER_WRITER_NP
    2, // PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP
];

fn glibc_roundtrip(kind: c_int) -> (c_int, c_int) {
    // glibc attr is up to 8 bytes; use a generous aligned buffer.
    let mut buf = [0u64; 1];
    let attr = buf.as_mut_ptr() as *mut c_void;
    assert_eq!(unsafe { pthread_rwlockattr_init(attr) }, 0);
    let set_rc = unsafe { pthread_rwlockattr_setkind_np(attr, kind) };
    let mut got = -1;
    let get_rc = unsafe { pthread_rwlockattr_getkind_np(attr, &mut got) };
    assert_eq!(get_rc, 0);
    (set_rc, got)
}

fn fl_roundtrip(kind: c_int) -> (c_int, c_int) {
    let mut buf = [0u64; 1];
    let attr = buf.as_mut_ptr() as *mut c_void;
    assert_eq!(unsafe { fl_init(attr.cast()) }, 0);
    let set_rc = unsafe { fl_setkind(attr, kind) };
    let mut got = -1;
    let get_rc = unsafe { fl_getkind(attr as *const c_void, &mut got) };
    assert_eq!(get_rc, 0);
    (set_rc, got)
}

#[test]
fn kind_round_trips_like_glibc() {
    for k in KINDS {
        let (gset, gkind) = glibc_roundtrip(k);
        let (fset, fkind) = fl_roundtrip(k);
        assert_eq!(gset, 0, "glibc setkind({k}) should succeed");
        assert_eq!(gkind, k, "glibc getkind must return what was set");
        assert_eq!(fset, gset, "fl setkind rc mismatch for kind {k}");
        assert_eq!(fkind, k, "fl getkind returned {fkind}, expected {k}");
    }
}

#[test]
fn invalid_kind_rejected_like_glibc() {
    let mut buf = [0u64; 1];
    let attr = buf.as_mut_ptr() as *mut c_void;
    assert_eq!(unsafe { fl_init(attr.cast()) }, 0);
    for bad in [-1, 3, 99, c_int::MIN, c_int::MAX] {
        assert_eq!(
            unsafe { fl_setkind(attr, bad) },
            libc::EINVAL,
            "fl setkind({bad}) must be EINVAL"
        );
    }
}

#[test]
fn kind_survives_setpshared_and_is_independent() {
    // Setting pshared must not clobber a previously-set kind, and getpshared
    // must reflect pshared regardless of kind.
    let mut buf = [0u64; 1];
    let attr = buf.as_mut_ptr() as *mut c_void;
    assert_eq!(unsafe { fl_init(attr.cast()) }, 0);

    assert_eq!(
        unsafe { fl_setkind(attr, 2) },
        0,
        "set kind=PREFER_WRITER_NONRECURSIVE"
    );
    assert_eq!(
        unsafe { fl_setpshared(attr.cast(), libc::PTHREAD_PROCESS_SHARED) },
        0
    );

    let mut kind = -1;
    assert_eq!(unsafe { fl_getkind(attr as *const c_void, &mut kind) }, 0);
    assert_eq!(kind, 2, "kind must survive setpshared");

    let mut pshared = -1;
    assert_eq!(unsafe { fl_getpshared(attr.cast(), &mut pshared) }, 0);
    assert_eq!(
        pshared,
        libc::PTHREAD_PROCESS_SHARED,
        "pshared must be reported independently of kind"
    );
}
