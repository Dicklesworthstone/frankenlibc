#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc lchmod oracle + real filesystem

//! Behavioral gate for lchmod's symlink-nofollow contract (bd-u9xw8a, pinning
//! bd-f29d1s). lchmod must NOT follow a symlink: on Linux the kernel cannot
//! change a symlink's mode, so lchmod(symlink) fails (EOPNOTSUPP) and the
//! TARGET file's mode is left untouched. The old fl dropped AT_SYMLINK_NOFOLLOW
//! and chmod'd the target. fl must now match host glibc on the return/errno AND
//! leave the target unchanged; on a regular file lchmod still changes the mode.
//! No mocks — real files + real glibc.

use std::ffi::{c_char, c_int, c_uint, CString};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

unsafe extern "C" {
    fn lchmod(path: *const c_char, mode: c_uint) -> c_int;
    fn __errno_location() -> *mut c_int;
}

static CNT: AtomicU64 = AtomicU64::new(0);
fn tmpbase(tag: &str) -> std::path::PathBuf {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-lchmod-{}-{}-{}", std::process::id(), tag, n));
    p
}

fn mode_of(p: &std::path::Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
}

fn cstr(p: &std::path::Path) -> CString {
    CString::new(p.to_string_lossy().as_bytes()).unwrap()
}

/// Run lchmod(link -> target) for one impl; returns (rc, errno, target_mode).
fn run(lchmod_fn: impl Fn(*const c_char, c_uint) -> c_int, tag: &str) -> (c_int, c_int, u32) {
    let target = tmpbase(&format!("{tag}-tgt"));
    let link = tmpbase(&format!("{tag}-lnk"));
    std::fs::write(&target, b"x").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let c = cstr(&link);
    unsafe { *__errno_location() = 0 };
    let rc = lchmod_fn(c.as_ptr(), 0o600);
    let err = unsafe { *__errno_location() };
    let tmode = mode_of(&target);
    let _ = std::fs::remove_file(&link);
    let _ = std::fs::remove_file(&target);
    (rc, err, tmode)
}

#[test]
fn lchmod_on_symlink_matches_glibc_and_spares_target() {
    let g = run(|p, m| unsafe { lchmod(p, m) }, "g");
    let f = run(|p, m| unsafe { frankenlibc_abi::glibc_internal_abi::lchmod(p, m) }, "f");

    // The target's mode must be untouched in BOTH (lchmod must not follow).
    assert_eq!(g.2, 0o644, "glibc lchmod must not change the symlink target mode");
    assert_eq!(f.2, 0o644, "fl lchmod must not change the symlink target mode (bd-f29d1s)");
    // Return code agreement (both fail to chmod a symlink).
    assert_eq!(f.0, g.0, "lchmod(symlink) rc: fl={} glibc={}", f.0, g.0);
    if f.0 != 0 {
        assert_eq!(f.1, g.1, "lchmod(symlink) errno: fl={} glibc={}", f.1, g.1);
    }
}

#[test]
fn lchmod_on_regular_file_changes_mode() {
    // For a non-symlink, AT_SYMLINK_NOFOLLOW is a no-op: lchmod changes the mode.
    let file = tmpbase("reg");
    std::fs::write(&file, b"x").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let c = cstr(&file);
    let rc = unsafe { frankenlibc_abi::glibc_internal_abi::lchmod(c.as_ptr(), 0o600) };
    let mode = mode_of(&file);
    let _ = std::fs::remove_file(&file);
    assert_eq!(rc, 0, "lchmod on a regular file should succeed");
    assert_eq!(mode, 0o600, "lchmod on a regular file should change the mode");
}
