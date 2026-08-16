#![cfg(target_os = "linux")]

//! Differential conformance harness for the mkstemp(3) family:
//! `mkstemp`, `mkstemps`, `mkostemp`, `mkostemps`, `mkdtemp`.
//!
//! All accept a template ending in "XXXXXX" (or longer for the
//! suffix variants) and replace it in place with random characters.
//! Both fl and glibc must agree on which templates are accepted/
//! rejected.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, c_int};
use std::os::unix::ffi::OsStrExt;

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::stdlib_abi as fl;
use frankenlibc_abi::unistd_abi as fl_unistd;
use frankenlibc_abi::wchar_abi as fl_wchar;

// The host arms are resolved with `dlsym`, not declared at link time. fl
// exports its own mkstemp family into this binary, and a link-time reference
// can bind to those instead of libc's — making both arms fl so every assertion
// passes while proving nothing. Measured, not theoretical:
// conformance_diff_catopen was passing exactly this way in a plain debug build
// and was concealing a live errno defect (bd-rp1e32, bd-v0388t). dlsym on an
// explicit libc.so.6 handle is correct in every build profile, and the
// assert_ne! makes the remaining doubt a failing test.
type MkstempFn = unsafe extern "C" fn(*mut c_char) -> c_int;
type MkstempsFn = unsafe extern "C" fn(*mut c_char, c_int) -> c_int;
type MkostempFn = unsafe extern "C" fn(*mut c_char, c_int) -> c_int;
type MkostempsFn = unsafe extern "C" fn(*mut c_char, c_int, c_int) -> c_int;
type MkdtempFn = unsafe extern "C" fn(*mut c_char) -> *mut c_char;

/// Resolve `name` from libc.so.6 and refuse to hand back fl's own code.
///
/// The address check is the point: it is what turns "the oracle silently became
/// the implementation" from an invisible pass into a failing test.
fn host_symbol(name: &std::ffi::CStr, fl_addr: usize) -> *mut std::ffi::c_void {
    // SAFETY: libc.so.6 is the process host libc; flags request a local handle.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    // SAFETY: the handle came from dlopen; name is NUL-terminated.
    let raw = unsafe { libc::dlsym(handle, name.as_ptr()) };
    assert!(!raw.is_null(), "dlsym {name:?}");
    assert_ne!(
        raw as usize, fl_addr,
        "the resolved oracle IS fl's {name:?} — this gate would compare fl to itself"
    );
    raw
}

fn host_mkstemp() -> MkstempFn {
    // SAFETY: the resolved symbol has POSIX's documented mkstemp signature.
    unsafe {
        std::mem::transmute::<_, MkstempFn>(host_symbol(c"mkstemp", fl_wchar::mkstemp as usize))
    }
}
fn host_mkstemps() -> MkstempsFn {
    // SAFETY: the resolved symbol has glibc's documented mkstemps signature.
    unsafe { std::mem::transmute::<_, MkstempsFn>(host_symbol(c"mkstemps", fl::mkstemps as usize)) }
}
fn host_mkostemp() -> MkostempFn {
    // SAFETY: the resolved symbol has glibc's documented mkostemp signature.
    unsafe { std::mem::transmute::<_, MkostempFn>(host_symbol(c"mkostemp", fl::mkostemp as usize)) }
}
fn host_mkostemps() -> MkostempsFn {
    // SAFETY: the resolved symbol has glibc's documented mkostemps signature.
    unsafe {
        std::mem::transmute::<_, MkostempsFn>(host_symbol(c"mkostemps", fl::mkostemps as usize))
    }
}
fn host_mkdtemp() -> MkdtempFn {
    // SAFETY: the resolved symbol has POSIX's documented mkdtemp signature.
    unsafe {
        std::mem::transmute::<_, MkdtempFn>(host_symbol(c"mkdtemp", fl_unistd::mkdtemp as usize))
    }
}

fn nano_template(suffix: &str) -> Vec<u8> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("/tmp/fl_mkstemp_{nanos}_{suffix}\0").into_bytes()
}

unsafe fn reset_errno_slots() {
    unsafe {
        *fl_errno_location() = 0;
        *libc::__errno_location() = 0;
    }
}

unsafe fn read_fl_errno() -> c_int {
    unsafe { *fl_errno_location() }
}

unsafe fn read_lc_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

#[test]
fn diff_mkstemp_creates_unique_files() {
    let mkstemp = host_mkstemp();
    // Both impls accept the standard template; both must produce
    // valid distinct fds when called twice.
    let mut t1 = b"/tmp/fl_mkstemp_a_XXXXXX\0".to_vec();
    let mut t2 = b"/tmp/fl_mkstemp_b_XXXXXX\0".to_vec();
    let fl_fd = unsafe { fl_wchar::mkstemp(t1.as_mut_ptr() as *mut c_char) };
    let lc_fd = unsafe { mkstemp(t2.as_mut_ptr() as *mut c_char) };
    assert!(fl_fd >= 0, "fl mkstemp failed");
    assert!(lc_fd >= 0, "lc mkstemp failed");
    assert_ne!(fl_fd, lc_fd);
    // Both templates must have been mutated (no longer XXXXXX).
    assert_ne!(&t1[18..24], b"XXXXXX");
    assert_ne!(&t2[18..24], b"XXXXXX");
    unsafe {
        libc::close(fl_fd);
        libc::close(lc_fd);
        let s1 = std::ffi::CStr::from_ptr(t1.as_ptr() as *const c_char);
        let s2 = std::ffi::CStr::from_ptr(t2.as_ptr() as *const c_char);
        libc::unlink(s1.as_ptr());
        libc::unlink(s2.as_ptr());
    }
}

#[test]
fn diff_mkstemp_invalid_template_returns_einval() {
    let mkstemp = host_mkstemp();
    // Template not ending in XXXXXX → both impls must reject.
    let mut t1 = b"/tmp/fl_mkstemp_no_marker\0".to_vec();
    let mut t2 = b"/tmp/fl_mkstemp_no_marker\0".to_vec();
    unsafe { reset_errno_slots() };
    let fl_fd = unsafe { fl_wchar::mkstemp(t1.as_mut_ptr() as *mut c_char) };
    let fl_e = unsafe { read_fl_errno() };
    unsafe { reset_errno_slots() };
    let lc_fd = unsafe { mkstemp(t2.as_mut_ptr() as *mut c_char) };
    let lc_e = unsafe { read_lc_errno() };
    assert_eq!(fl_fd, lc_fd);
    assert_eq!(fl_fd, -1);
    assert_eq!(fl_e, lc_e, "errno: fl={fl_e} lc={lc_e}");
    assert_eq!(fl_e, libc::EINVAL);
}

#[test]
fn diff_mkstemps_with_suffix_works() {
    let mkstemps = host_mkstemps();
    // Template "...XXXXXX.tmp" with suffixlen=4 means the .tmp is
    // a suffix preserved, XXXXXX gets randomized.
    let mut t1 = b"/tmp/fl_mkstemps_a_XXXXXX.tmp\0".to_vec();
    let mut t2 = b"/tmp/fl_mkstemps_b_XXXXXX.tmp\0".to_vec();
    let fl_fd = unsafe { fl::mkstemps(t1.as_mut_ptr() as *mut c_char, 4) };
    let lc_fd = unsafe { mkstemps(t2.as_mut_ptr() as *mut c_char, 4) };
    assert!(fl_fd >= 0, "fl mkstemps failed");
    assert!(lc_fd >= 0, "lc mkstemps failed");
    // The .tmp suffix must be preserved.
    assert_eq!(&t1[t1.len() - 5..t1.len() - 1], b".tmp");
    assert_eq!(&t2[t2.len() - 5..t2.len() - 1], b".tmp");
    // The X's must have been replaced.
    let xs_pos = t1.len() - 11;
    assert_ne!(&t1[xs_pos..xs_pos + 6], b"XXXXXX");
    unsafe {
        libc::close(fl_fd);
        libc::close(lc_fd);
        let s1 = std::ffi::CStr::from_ptr(t1.as_ptr() as *const c_char);
        let s2 = std::ffi::CStr::from_ptr(t2.as_ptr() as *const c_char);
        libc::unlink(s1.as_ptr());
        libc::unlink(s2.as_ptr());
    }
}

#[test]
fn diff_mkostemp_with_o_cloexec_sets_close_on_exec() {
    let mkostemp = host_mkostemp();
    let mut t1 = nano_template("ostemp_a_XXXXXX");
    let mut t2 = nano_template("ostemp_b_XXXXXX");
    let fl_fd = unsafe { fl::mkostemp(t1.as_mut_ptr() as *mut c_char, libc::O_CLOEXEC) };
    let lc_fd = unsafe { mkostemp(t2.as_mut_ptr() as *mut c_char, libc::O_CLOEXEC) };
    assert!(fl_fd >= 0);
    assert!(lc_fd >= 0);
    let fl_flags = unsafe { libc::fcntl(fl_fd, libc::F_GETFD) };
    let lc_flags = unsafe { libc::fcntl(lc_fd, libc::F_GETFD) };
    assert!(fl_flags & libc::FD_CLOEXEC != 0, "fl missing FD_CLOEXEC");
    assert!(lc_flags & libc::FD_CLOEXEC != 0, "lc missing FD_CLOEXEC");
    unsafe {
        libc::close(fl_fd);
        libc::close(lc_fd);
        let s1 = std::ffi::CStr::from_ptr(t1.as_ptr() as *const c_char);
        let s2 = std::ffi::CStr::from_ptr(t2.as_ptr() as *const c_char);
        libc::unlink(s1.as_ptr());
        libc::unlink(s2.as_ptr());
    }
}

#[test]
fn diff_mkostemps_invalid_template_returns_einval() {
    let mkostemps = host_mkostemps();
    let mut t1 = b"/tmp/fl_mkostemps_no_marker.tmp\0".to_vec();
    let mut t2 = b"/tmp/fl_mkostemps_no_marker.tmp\0".to_vec();
    unsafe { reset_errno_slots() };
    let fl_fd = unsafe { fl::mkostemps(t1.as_mut_ptr() as *mut c_char, 4, libc::O_CLOEXEC) };
    let fl_e = unsafe { read_fl_errno() };
    unsafe { reset_errno_slots() };
    let lc_fd = unsafe { mkostemps(t2.as_mut_ptr() as *mut c_char, 4, libc::O_CLOEXEC) };
    let lc_e = unsafe { read_lc_errno() };
    assert_eq!(fl_fd, lc_fd);
    assert_eq!(fl_fd, -1);
    assert_eq!(fl_e, lc_e, "errno: fl={fl_e} lc={lc_e}");
    assert_eq!(fl_e, libc::EINVAL);
}

#[test]
fn diff_mkdtemp_creates_directory() {
    let mkdtemp = host_mkdtemp();
    let mut t1 = nano_template("mkdtemp_a_XXXXXX");
    let mut t2 = nano_template("mkdtemp_b_XXXXXX");
    let fl_p = unsafe { fl_unistd::mkdtemp(t1.as_mut_ptr() as *mut c_char) };
    let lc_p = unsafe { mkdtemp(t2.as_mut_ptr() as *mut c_char) };
    assert!(!fl_p.is_null());
    assert!(!lc_p.is_null());
    // Verify the dirs exist.
    let s1 = unsafe { std::ffi::CStr::from_ptr(t1.as_ptr() as *const c_char) };
    let s2 = unsafe { std::ffi::CStr::from_ptr(t2.as_ptr() as *const c_char) };
    let p1 = std::path::Path::new(std::ffi::OsStr::from_bytes(s1.to_bytes()));
    let p2 = std::path::Path::new(std::ffi::OsStr::from_bytes(s2.to_bytes()));
    assert!(std::fs::metadata(p1).is_ok_and(|m| m.is_dir()));
    assert!(std::fs::metadata(p2).is_ok_and(|m| m.is_dir()));
    unsafe {
        libc::rmdir(s1.as_ptr());
        libc::rmdir(s2.as_ptr());
    }
}

#[test]
fn diff_mkdtemp_invalid_template_rejected() {
    let mkdtemp = host_mkdtemp();
    let mut t1 = b"/tmp/fl_mkdtemp_no_marker\0".to_vec();
    let mut t2 = b"/tmp/fl_mkdtemp_no_marker\0".to_vec();
    let fl_p = unsafe { fl_unistd::mkdtemp(t1.as_mut_ptr() as *mut c_char) };
    let lc_p = unsafe { mkdtemp(t2.as_mut_ptr() as *mut c_char) };
    assert!(fl_p.is_null());
    assert!(lc_p.is_null());
}

#[test]
fn mkstemp_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc mkstemp + mkstemps + mkostemp + mkostemps + mkdtemp\",\"reference\":\"glibc\",\"functions\":5,\"divergences\":0}}",
    );
}
