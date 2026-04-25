#![cfg(target_os = "linux")]

//! Integration tests for err.h ABI entrypoints (warn/warnx only;
//! err/errx call _exit and cannot be tested in-process).

use frankenlibc_abi::err_abi::{vwarn, vwarnc, vwarnx, warn, warnc, warnx};
use std::ffi::c_char;

// ---------------------------------------------------------------------------
// warn / warnx — these write to stderr but don't exit
// ---------------------------------------------------------------------------

#[test]
fn test_warn_null_fmt() {
    // warn(NULL) should print "progname: strerror(errno)\n" without crashing.
    unsafe { warn(std::ptr::null()) };
}

#[test]
fn test_warn_simple_message() {
    let msg = b"test message %d\0";
    // This will print "progname: test message <garbage>: strerror(errno)\n"
    // We just verify it doesn't crash.
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warn_empty_fmt() {
    let msg = b"\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warn_long_message() {
    // Test with a longer format string
    let msg = b"this is a longer warning message with no format specifiers\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warn_percent_literal() {
    // Test %% (literal percent) in format string
    let msg = b"100%% complete\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warnx_null_fmt() {
    // warnx(NULL) should print "progname: \n" without crashing.
    unsafe { warnx(std::ptr::null()) };
}

#[test]
fn test_warnx_simple_message() {
    let msg = b"simple warning\0";
    unsafe { warnx(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warnx_empty_fmt() {
    let msg = b"\0";
    unsafe { warnx(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warnx_long_message() {
    let msg = b"this is a warnx message without errno appended\0";
    unsafe { warnx(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warnx_percent_literal() {
    let msg = b"50%% done\0";
    unsafe { warnx(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_vwarn_null_fmt() {
    unsafe { vwarn(std::ptr::null(), std::ptr::null_mut()) };
}

#[test]
fn test_vwarnx_null_fmt() {
    unsafe { vwarnx(std::ptr::null(), std::ptr::null_mut()) };
}

// ---------------------------------------------------------------------------
// warn/warnx with errno set — verify errno context doesn't crash
// ---------------------------------------------------------------------------

#[test]
fn test_warn_with_enoent_errno() {
    // Set errno to ENOENT, then call warn — should include "No such file..."
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::ENOENT };
    let msg = b"open failed\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warn_with_eperm_errno() {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::EPERM };
    let msg = b"permission check\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warn_with_zero_errno() {
    // errno=0 → "Success"
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = 0 };
    let msg = b"no error\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warn_preserves_errno() {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::EACCES };
    let msg = b"errno preserved\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
    assert_eq!(
        unsafe { *frankenlibc_abi::errno_abi::__errno_location() },
        libc::EACCES
    );
}

#[test]
fn test_warnx_preserves_errno() {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::ENOENT };
    let msg = b"warnx errno preserved\0";
    unsafe { warnx(msg.as_ptr() as *const c_char) };
    assert_eq!(
        unsafe { *frankenlibc_abi::errno_abi::__errno_location() },
        libc::ENOENT
    );
}

// ---------------------------------------------------------------------------
// Multiple sequential calls — exercise progname caching
// ---------------------------------------------------------------------------

#[test]
fn test_warn_warnx_interleaved() {
    let w1 = b"first warn\0";
    let w2 = b"then warnx\0";
    let w3 = b"back to warn\0";
    unsafe {
        warn(w1.as_ptr() as *const c_char);
        warnx(w2.as_ptr() as *const c_char);
        warn(w3.as_ptr() as *const c_char);
    }
}

// ---------------------------------------------------------------------------
// Thread safety — concurrent warn/warnx calls
// ---------------------------------------------------------------------------

#[test]
fn test_warn_concurrent() {
    let handles: Vec<_> = (0..4)
        .map(|i| {
            std::thread::spawn(move || {
                let msg = format!("thread {} warning\0", i);
                unsafe { warn(msg.as_ptr() as *const c_char) };
                unsafe { warnx(msg.as_ptr() as *const c_char) };
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

// ---------------------------------------------------------------------------
// vwarn/vwarnx with non-null fmt strings
// ---------------------------------------------------------------------------

#[test]
fn test_vwarn_with_message() {
    let msg = b"vwarn test\0";
    unsafe { vwarn(msg.as_ptr() as *const c_char, std::ptr::null_mut()) };
}

#[test]
fn test_vwarnx_with_message() {
    let msg = b"vwarnx test\0";
    unsafe { vwarnx(msg.as_ptr() as *const c_char, std::ptr::null_mut()) };
}

// ---------------------------------------------------------------------------
// warn with various errno values — exercise strerror path
// ---------------------------------------------------------------------------

#[test]
fn test_warn_with_eacces_errno() {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::EACCES };
    let msg = b"access denied\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warn_with_enomem_errno() {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::ENOMEM };
    let msg = b"out of memory\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warn_with_eio_errno() {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::EIO };
    let msg = b"io error\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warn_with_enosys_errno() {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::ENOSYS };
    let msg = b"not implemented\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

// ---------------------------------------------------------------------------
// Rapid fire — exercise format caching
// ---------------------------------------------------------------------------

#[test]
fn test_warn_rapid_fire() {
    for i in 0..20 {
        let msg = format!("rapid warn {}\0", i);
        unsafe { warn(msg.as_ptr() as *const c_char) };
    }
}

#[test]
fn test_warnx_rapid_fire() {
    for i in 0..20 {
        let msg = format!("rapid warnx {}\0", i);
        unsafe { warnx(msg.as_ptr() as *const c_char) };
    }
}

// ---------------------------------------------------------------------------
// warn/warnx alternating with errno changes
// ---------------------------------------------------------------------------

#[test]
fn test_warn_alternating_errno() {
    let errnos = [libc::ENOENT, libc::EINVAL, libc::EPERM, libc::EACCES, 0];
    for &e in &errnos {
        unsafe { *frankenlibc_abi::errno_abi::__errno_location() = e };
        let msg = b"alternating\0";
        unsafe { warn(msg.as_ptr() as *const c_char) };
    }
}

// ---------------------------------------------------------------------------
// warnc / vwarnc — BSD/NetBSD explicit-code variants
// ---------------------------------------------------------------------------

#[test]
fn test_warnc_uses_explicit_code_not_global_errno() {
    // Set the global to one value, pass a *different* code to warnc;
    // both calls must succeed without crashing and global errno must
    // be preserved across the call (matches warn()'s contract).
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::EACCES };
    let msg = b"warnc explicit-code test\0";
    unsafe { warnc(libc::ENOENT, msg.as_ptr() as *const c_char) };
    assert_eq!(
        unsafe { *frankenlibc_abi::errno_abi::__errno_location() },
        libc::EACCES,
        "warnc must preserve the global errno"
    );
}

#[test]
fn test_warnc_null_fmt_uses_code() {
    // NULL format with an explicit code — must not crash and must use
    // the supplied code's strerror, not the global.
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::EIO };
    unsafe { warnc(libc::ENOMEM, std::ptr::null()) };
    assert_eq!(
        unsafe { *frankenlibc_abi::errno_abi::__errno_location() },
        libc::EIO,
        "warnc(NULL, code) must preserve global errno"
    );
}

#[test]
fn test_warnc_zero_code_is_success_message() {
    // code=0 → strerror(0) → typically "Success".
    let msg = b"zero code\0";
    unsafe { warnc(0, msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warnc_with_format_args() {
    // Arguments must be extracted correctly from varargs.
    let msg = b"warnc with arg %d\0";
    unsafe { warnc(libc::EINVAL, msg.as_ptr() as *const c_char, 42i32) };
}

#[test]
fn test_warnc_rapid_fire_different_codes() {
    let codes = [
        libc::ENOENT,
        libc::EINVAL,
        libc::EPERM,
        libc::EACCES,
        libc::ENOMEM,
        libc::EIO,
    ];
    for &c in &codes {
        let msg = b"rapid warnc\0";
        unsafe { warnc(c, msg.as_ptr() as *const c_char) };
    }
}

#[test]
fn test_vwarnc_null_fmt() {
    unsafe { vwarnc(libc::ENOENT, std::ptr::null(), std::ptr::null_mut()) };
}

#[test]
fn test_vwarnc_with_message() {
    let msg = b"vwarnc test\0";
    unsafe {
        vwarnc(
            libc::EPERM,
            msg.as_ptr() as *const c_char,
            std::ptr::null_mut(),
        )
    };
}

#[test]
fn test_vwarnc_preserves_global_errno() {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::EACCES };
    let msg = b"vwarnc preserve errno\0";
    unsafe {
        vwarnc(
            libc::ENOSYS,
            msg.as_ptr() as *const c_char,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(
        unsafe { *frankenlibc_abi::errno_abi::__errno_location() },
        libc::EACCES,
        "vwarnc must preserve global errno across the call"
    );
}

#[test]
fn test_warnc_concurrent() {
    // Concurrent warnc calls with different codes — exercises the
    // shared progname cache + per-call code path.
    let handles: Vec<_> = (0..4)
        .map(|i| {
            std::thread::spawn(move || {
                let msg = format!("thread {} warnc\0", i);
                let codes = [libc::ENOENT, libc::EINVAL, libc::EPERM, libc::EIO];
                unsafe { warnc(codes[i % 4], msg.as_ptr() as *const c_char) };
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}
