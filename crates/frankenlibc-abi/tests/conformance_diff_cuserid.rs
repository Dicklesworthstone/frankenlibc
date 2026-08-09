#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc cuserid oracle

//! Host-differential gate for `cuserid(3)` (bd-l1xxt3).
//!
//! cuserid had buffer/passwd-backend coverage driven through fl's
//! `FRANKENLIBC_PASSWD_PATH` override, but nothing that compared it against the
//! host. That override is exactly what made the gap invisible: a test that
//! points fl at a synthetic passwd file proves fl parses that file, not that fl
//! agrees with glibc about the real one. This gate deliberately does NOT set the
//! override, so both implementations resolve the same live /etc/passwd for the
//! same uid.
//!
//! That distinction is not hypothetical here. cuserid was a hardcoded
//! `if uid == 0 { "root" } else { "user" }` stub until daaed5036 restored the
//! passwd lookup that e634aff2a had deleted, and the stub would have sailed
//! through any override-driven test that happened to expect "user" — while
//! failing this one for every non-root account.
//!
//! glibc's cuserid is reached through a plain `extern "C"`: fl's definitions
//! carry `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`, so their
//! no_mangle is off in a debug build and these symbols resolve to the host.
//!
//! KNOWN WEAKNESS ON A ROOT HOST — measured, not theorised. The old stub
//! answered `uid == 0 ? "root" : "user"`, and for uid 0 that is ALSO the correct
//! passwd answer. So on the rch fleet, whose workers run as root, this gate
//! cannot distinguish the stub from a working lookup: re-introducing the stub
//! as a mutation leaves all three tests green. It discriminates properly for any
//! non-root uid (the stub would say "user" where the host says e.g. "ubuntu"),
//! which is the common case on a developer machine and in CI running unprivileged.
//!
//! Strengthening it for a root host means forking a child, setuid-ing to a
//! non-root account, and comparing there — deliberately NOT done here, because
//! forking inside this suite has its own hazards and the arm would exist only to
//! serve one environment. Tracked on bd-l1xxt3 instead of being left implicit.

use std::ffi::{CStr, c_char};

unsafe extern "C" {
    fn cuserid(s: *mut c_char) -> *mut c_char;
}

/// L_cuserid is 9 on glibc, but fl's internal buffer is 32 and the caller-buffer
/// form is documented against L_cuserid. Give both engines the same generous
/// buffer so a difference in RESULT is never confused with a difference in the
/// space they were handed.
const BUF: usize = 64;

fn caller_buffer(engine: u8) -> Option<Vec<u8>> {
    let mut buf = [0 as c_char; BUF];
    let p = if engine == 0 {
        unsafe { frankenlibc_abi::unistd_abi::cuserid(buf.as_mut_ptr()) }
    } else {
        unsafe { cuserid(buf.as_mut_ptr()) }
    };
    if p.is_null() {
        return None;
    }
    // Both must hand back the caller's own pointer, not internal storage.
    assert_eq!(
        p,
        buf.as_mut_ptr(),
        "cuserid(buf) must return the caller's buffer"
    );
    Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

fn static_storage(engine: u8) -> Option<Vec<u8>> {
    let p = if engine == 0 {
        unsafe { frankenlibc_abi::unistd_abi::cuserid(std::ptr::null_mut()) }
    } else {
        unsafe { cuserid(std::ptr::null_mut()) }
    };
    if p.is_null() {
        return None;
    }
    Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

#[test]
fn cuserid_caller_buffer_matches_glibc() {
    let fl = caller_buffer(0);
    let host = caller_buffer(1);
    assert_eq!(
        fl.as_deref().map(String::from_utf8_lossy),
        host.as_deref().map(String::from_utf8_lossy),
        "cuserid(buf): fl={:?} glibc={:?}",
        fl.as_deref().map(String::from_utf8_lossy),
        host.as_deref().map(String::from_utf8_lossy)
    );

    // Guard against BOTH sides being trivially empty, which would make the
    // comparison above vacuous. The process always runs as some real uid, so a
    // non-empty login name is the expected outcome on any sane host.
    let name = host.expect("host cuserid returned NULL");
    assert!(
        !name.is_empty(),
        "host cuserid produced an empty name; the comparison would prove nothing"
    );
}

#[test]
fn cuserid_static_storage_matches_glibc() {
    let fl = static_storage(0);
    let host = static_storage(1);
    assert_eq!(
        fl.as_deref().map(String::from_utf8_lossy),
        host.as_deref().map(String::from_utf8_lossy),
        "cuserid(NULL): fl={:?} glibc={:?}",
        fl.as_deref().map(String::from_utf8_lossy),
        host.as_deref().map(String::from_utf8_lossy)
    );
}

#[test]
fn cuserid_both_forms_agree_within_each_impl() {
    // The NULL form and the caller-buffer form must produce the same name in a
    // single implementation. This is what would catch the restored code
    // truncating one path and not the other — the stub capped the caller buffer
    // at 8 bytes while the static path used the full width, so the two forms
    // could disagree for a login name longer than 8 characters.
    for (engine, label) in [(0u8, "frankenlibc"), (1u8, "glibc")] {
        let via_buf = caller_buffer(engine);
        let via_static = static_storage(engine);
        assert_eq!(
            via_buf.as_deref().map(String::from_utf8_lossy),
            via_static.as_deref().map(String::from_utf8_lossy),
            "{label}: cuserid(buf) and cuserid(NULL) disagree"
        );
    }
}
