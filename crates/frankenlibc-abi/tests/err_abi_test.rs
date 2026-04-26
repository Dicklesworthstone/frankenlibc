#![cfg(target_os = "linux")]

//! Integration tests for err.h ABI entrypoints (warn/warnx only;
//! err/errx call _exit and cannot be tested in-process).

use frankenlibc_abi::err_abi::{err_set_exit, vwarn, vwarnc, vwarnx, warn, warnc, warnx};
use std::ffi::{c_char, c_int};

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

// ---------------------------------------------------------------------------
// err_set_exit (BSD libutil pre-exit hook)
// ---------------------------------------------------------------------------

/// Serialize tests that touch the global err-exit hook so they
/// can't observe each other's mutations.
static ERR_SET_EXIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

unsafe extern "C" fn dummy_hook_a(_eval: c_int) {}
unsafe extern "C" fn dummy_hook_b(_eval: c_int) {}

#[test]
fn err_set_exit_returns_previous_hook() {
    let _guard = ERR_SET_EXIT_LOCK.lock().unwrap();
    // Start from a known clean state.
    let saved = unsafe { err_set_exit(None) };

    // Install A → previous is None.
    let prev = unsafe { err_set_exit(Some(dummy_hook_a)) };
    assert!(prev.is_none(), "first install should report no prior hook");

    // Install B → previous is A.
    let prev = unsafe { err_set_exit(Some(dummy_hook_b)) };
    assert!(prev.is_some());
    assert_eq!(
        prev.unwrap() as *const () as usize,
        dummy_hook_a as *const () as usize,
        "swap should report the prior hook"
    );

    // Clear → previous is B.
    let prev = unsafe { err_set_exit(None) };
    assert!(prev.is_some());
    assert_eq!(
        prev.unwrap() as *const () as usize,
        dummy_hook_b as *const () as usize
    );

    // Final clear should yield None.
    let after = unsafe { err_set_exit(None) };
    assert!(after.is_none());

    // Restore whatever was installed before the test.
    unsafe { err_set_exit(saved) };
}

#[test]
fn err_set_exit_hook_runs_before_errx_in_child() {
    // Run a fresh test-binary child instead of forking from this
    // multi-threaded harness. Calling mutex-backed Rust code after
    // fork can deadlock if another test thread owned runtime state.
    let _guard = ERR_SET_EXIT_LOCK.lock().unwrap();

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--ignored")
        .arg("--exact")
        .arg("err_set_exit_child_process")
        .arg("--nocapture")
        .env("FLC_ERR_SET_EXIT_CHILD", "1")
        .output()
        .expect("failed to run err_set_exit child process");

    assert_eq!(
        output.status.code(),
        Some(7),
        "child should exit via errx(7)"
    );
    assert!(
        output.stderr.contains(&7),
        "child hook did not write eval marker to stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output
            .stderr
            .windows(b"err_set_exit child".len())
            .any(|window| window == b"err_set_exit child"),
        "errx diagnostic missing from stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore]
fn err_set_exit_child_process() {
    if std::env::var_os("FLC_ERR_SET_EXIT_CHILD").is_none() {
        return;
    }

    use frankenlibc_abi::err_abi::errx;

    HOOK_PIPE_WRITE.store(libc::STDERR_FILENO, std::sync::atomic::Ordering::SeqCst);
    unsafe { err_set_exit(Some(child_hook)) };
    let fmt = c"err_set_exit child";
    unsafe { errx(7, fmt.as_ptr()) };
}

static HOOK_PIPE_WRITE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

unsafe extern "C" fn child_hook(eval: c_int) {
    let fd = HOOK_PIPE_WRITE.load(std::sync::atomic::Ordering::SeqCst);
    let bytes = [eval as u8];
    let _ = unsafe { libc::write(fd, bytes.as_ptr() as *const std::ffi::c_void, 1) };
}
