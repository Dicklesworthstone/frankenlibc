//! Integration tests for the NetBSD `efun(3)` family. We install a
//! test callback via `esetfunc` so failure paths can be exercised
//! without actually exiting the process.

use frankenlibc_abi::efun_abi::{
    EFunc, ecalloc, efopen, emalloc, erealloc, esetfunc, estrdup, estrlcat, estrlcpy, estrndup,
    estrtoi, estrtou,
};
use frankenlibc_abi::stdio_abi::fclose;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Serialize tests that touch the global efun cell — installing
/// a callback in one test must not leak into another.
static EFUN_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Counter incremented by the test callback so we can assert the
/// callback was invoked.
static CB_INVOCATIONS: AtomicUsize = AtomicUsize::new(0);
static LAST_CB_EVAL: AtomicUsize = AtomicUsize::new(0);

/// Non-variadic helper — defining a variadic fn in stable Rust
/// requires nightly. The wrapper layer always invokes the
/// callback with no varargs, so this test callback observes the
/// fixed prefix args correctly.
unsafe extern "C" fn test_callback_non_variadic(eval: c_int, _fmt: *const c_char) {
    CB_INVOCATIONS.fetch_add(1, Ordering::SeqCst);
    LAST_CB_EVAL.store(eval as usize, Ordering::SeqCst);
}

fn test_callback() -> EFunc {
    // SAFETY: the wrapper layer never passes varargs, so the
    // function body never tries to read them. The fixed prefix
    // args (c_int, *const c_char) match in both signatures.
    unsafe {
        std::mem::transmute::<unsafe extern "C" fn(c_int, *const c_char), EFunc>(
            test_callback_non_variadic,
        )
    }
}

fn install_test_callback() -> Option<EFunc> {
    CB_INVOCATIONS.store(0, Ordering::SeqCst);
    LAST_CB_EVAL.store(0, Ordering::SeqCst);
    unsafe { esetfunc(Some(test_callback())) }
}

fn restore_callback(prev: Option<EFunc>) {
    unsafe { esetfunc(prev) };
}

#[test]
fn esetfunc_returns_previous_callback() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    // Installing test_callback again should return Some(test_callback).
    let prev = unsafe { esetfunc(Some(test_callback())) };
    assert!(prev.is_some());
    let prev_addr = prev.unwrap() as usize;
    let test_addr = test_callback() as usize;
    assert_eq!(prev_addr, test_addr);
    restore_callback(saved);
}

#[test]
fn esetfunc_can_install_and_clear() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let prev = unsafe { esetfunc(None) };
    assert!(prev.is_some());
    // After clearing, the next esetfunc call returns None.
    let after_clear = unsafe { esetfunc(None) };
    assert!(after_clear.is_none());
    restore_callback(saved);
}

#[test]
fn estrdup_success_passthrough() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let s = c"hello, efun!";
    let p = unsafe { estrdup(s.as_ptr()) };
    assert!(!p.is_null());
    assert_eq!(unsafe { CStr::from_ptr(p) }, s);
    unsafe { libc::free(p as *mut c_void) };
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 0);
    restore_callback(saved);
}

#[test]
fn estrdup_null_invokes_callback_and_returns_null() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let p = unsafe { estrdup(std::ptr::null()) };
    assert!(p.is_null());
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 1);
    assert_eq!(
        LAST_CB_EVAL.load(Ordering::SeqCst),
        libc::EXIT_FAILURE as usize
    );
    restore_callback(saved);
}

#[test]
fn estrndup_success_passthrough() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let s = c"banana";
    let p = unsafe { estrndup(s.as_ptr(), 3) };
    assert!(!p.is_null());
    assert_eq!(unsafe { CStr::from_ptr(p) }, c"ban");
    unsafe { libc::free(p as *mut c_void) };
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 0);
    restore_callback(saved);
}

#[test]
fn emalloc_success_passthrough() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let p = unsafe { emalloc(64) };
    assert!(!p.is_null());
    unsafe { libc::free(p) };
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 0);
    restore_callback(saved);
}

#[test]
fn emalloc_zero_size_does_not_invoke_callback() {
    // malloc(0) may legally return NULL or a unique pointer.
    // Either way the wrapper must not treat that as an error.
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let p = unsafe { emalloc(0) };
    if !p.is_null() {
        unsafe { libc::free(p) };
    }
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 0);
    restore_callback(saved);
}

#[test]
fn ecalloc_success_passthrough_and_zero_initialized() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let p = unsafe { ecalloc(8, 4) };
    assert!(!p.is_null());
    let bytes = unsafe { std::slice::from_raw_parts(p as *const u8, 32) };
    assert!(bytes.iter().all(|&b| b == 0));
    unsafe { libc::free(p) };
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 0);
    restore_callback(saved);
}

#[test]
fn ecalloc_zero_count_does_not_invoke_callback() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let p = unsafe { ecalloc(0, 16) };
    if !p.is_null() {
        unsafe { libc::free(p) };
    }
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 0);
    restore_callback(saved);
}

#[test]
fn erealloc_success_extends_and_preserves() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let p = unsafe { emalloc(8) };
    assert!(!p.is_null());
    unsafe {
        std::ptr::copy_nonoverlapping(b"abcdefgh".as_ptr(), p as *mut u8, 8);
    }
    let p2 = unsafe { erealloc(p, 32) };
    assert!(!p2.is_null());
    let preserved = unsafe { std::slice::from_raw_parts(p2 as *const u8, 8) };
    assert_eq!(preserved, b"abcdefgh");
    unsafe { libc::free(p2) };
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 0);
    restore_callback(saved);
}

#[test]
fn erealloc_to_zero_size_does_not_invoke_callback() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let p = unsafe { emalloc(16) };
    assert!(!p.is_null());
    let p2 = unsafe { erealloc(p, 0) };
    if !p2.is_null() {
        unsafe { libc::free(p2) };
    }
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 0);
    restore_callback(saved);
}

#[test]
fn estrlcpy_success_returns_source_length() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let mut buf = [0u8 as c_char; 16];
    let src = c"hello";
    let n = unsafe { estrlcpy(buf.as_mut_ptr(), src.as_ptr(), buf.len()) };
    assert_eq!(n, 5);
    assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()) }, src);
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 0);
    restore_callback(saved);
}

#[test]
fn estrlcpy_overflow_invokes_callback() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let mut buf = [0u8 as c_char; 4];
    let src = c"hello, world!";
    let _n = unsafe { estrlcpy(buf.as_mut_ptr(), src.as_ptr(), buf.len()) };
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 1);
    restore_callback(saved);
}

#[test]
fn estrlcpy_null_invokes_callback() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let n = unsafe { estrlcpy(std::ptr::null_mut(), c"x".as_ptr(), 8) };
    assert_eq!(n, 0);
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 1);
    restore_callback(saved);
}

#[test]
fn estrlcat_success_returns_combined_length() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let mut buf = [0u8 as c_char; 16];
    unsafe {
        std::ptr::copy_nonoverlapping(c"hi-".as_ptr() as *const u8, buf.as_mut_ptr() as *mut u8, 4);
    }
    let src = c"world";
    let n = unsafe { estrlcat(buf.as_mut_ptr(), src.as_ptr(), buf.len()) };
    assert_eq!(n, 8);
    assert_eq!(
        unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes(),
        b"hi-world"
    );
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 0);
    restore_callback(saved);
}

#[test]
fn estrlcat_overflow_invokes_callback() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let mut buf = [0u8 as c_char; 8];
    unsafe {
        std::ptr::copy_nonoverlapping(
            c"abcde".as_ptr() as *const u8,
            buf.as_mut_ptr() as *mut u8,
            6,
        );
    }
    let src = c"xyzwvu";
    let _ = unsafe { estrlcat(buf.as_mut_ptr(), src.as_ptr(), buf.len()) };
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 1);
    restore_callback(saved);
}

#[test]
fn efopen_success_passthrough() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let path = c"/etc/hostname";
    let mode = c"r";
    let f = unsafe { efopen(path.as_ptr(), mode.as_ptr()) };
    if !f.is_null() {
        // Best-effort: this file exists on most Linux systems.
        unsafe { fclose(f) };
        assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 0);
    }
    restore_callback(saved);
}

#[test]
fn efopen_nonexistent_path_invokes_callback() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let path = c"/nonexistent/path/that/should/not/exist/efun-test-xyz";
    let mode = c"r";
    let f = unsafe { efopen(path.as_ptr(), mode.as_ptr()) };
    assert!(f.is_null());
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 1);
    restore_callback(saved);
}

#[test]
fn efopen_null_args_invoke_callback() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let f = unsafe { efopen(std::ptr::null(), c"r".as_ptr()) };
    assert!(f.is_null());
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 1);
    restore_callback(saved);
}

// ---------------------------------------------------------------------------
// estrtoi / estrtou
// ---------------------------------------------------------------------------

#[test]
fn estrtoi_in_range_returns_value_silently() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let s = c"42";
    let v = unsafe { estrtoi(s.as_ptr(), 10, 0, 100) };
    assert_eq!(v, 42 as libc::intmax_t);
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 0);
    restore_callback(saved);
}

#[test]
fn estrtoi_no_digits_invokes_callback() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let s = c"   xyz";
    let _ = unsafe { estrtoi(s.as_ptr(), 10, 0, 100) };
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 1);
    restore_callback(saved);
}

#[test]
fn estrtoi_invalid_base_invokes_callback() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let s = c"42";
    let _ = unsafe { estrtoi(s.as_ptr(), 1, 0, 100) };
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 1);
    restore_callback(saved);
}

#[test]
fn estrtoi_out_of_range_invokes_callback_and_returns_clamped() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let s = c"500";
    let v = unsafe { estrtoi(s.as_ptr(), 10, 0, 100) };
    assert_eq!(v, 100 as libc::intmax_t);
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 1);
    restore_callback(saved);
}

#[test]
fn estrtoi_null_nptr_invokes_callback() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let v = unsafe { estrtoi(std::ptr::null(), 10, 0, 100) };
    assert_eq!(v, 0 as libc::intmax_t);
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 1);
    restore_callback(saved);
}

#[test]
fn estrtoi_negative_in_negative_range_silent() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let s = c"-12";
    let v = unsafe { estrtoi(s.as_ptr(), 10, -100, 100) };
    assert_eq!(v, -12 as libc::intmax_t);
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 0);
    restore_callback(saved);
}

#[test]
fn estrtou_in_range_returns_value_silently() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let s = c"42";
    let v = unsafe { estrtou(s.as_ptr(), 10, 0, 100) };
    assert_eq!(v, 42 as libc::uintmax_t);
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 0);
    restore_callback(saved);
}

#[test]
fn estrtou_above_hi_invokes_callback_and_returns_clamped() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let s = c"1000";
    let v = unsafe { estrtou(s.as_ptr(), 10, 0, 100) };
    assert_eq!(v, 100 as libc::uintmax_t);
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 1);
    restore_callback(saved);
}

#[test]
fn estrtou_no_digits_invokes_callback() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let s = c"abc";
    let _ = unsafe { estrtou(s.as_ptr(), 10, 0, 100) };
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 1);
    restore_callback(saved);
}

#[test]
fn estrtou_invalid_base_invokes_callback() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let s = c"42";
    let _ = unsafe { estrtou(s.as_ptr(), 99, 0, 100) };
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 1);
    restore_callback(saved);
}

#[test]
fn estrtou_null_nptr_invokes_callback() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let v = unsafe { estrtou(std::ptr::null(), 10, 0, 100) };
    assert_eq!(v, 0 as libc::uintmax_t);
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 1);
    restore_callback(saved);
}

#[test]
fn estrtou_hex_prefix_works() {
    let _guard = EFUN_TEST_LOCK.lock().unwrap();
    let saved = install_test_callback();
    let s = c"0xff";
    let v = unsafe { estrtou(s.as_ptr(), 16, 0, 0xffff) };
    assert_eq!(v, 0xff as libc::uintmax_t);
    assert_eq!(CB_INVOCATIONS.load(Ordering::SeqCst), 0);
    restore_callback(saved);
}
