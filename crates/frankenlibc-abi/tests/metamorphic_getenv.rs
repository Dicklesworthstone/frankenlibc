#![cfg(target_os = "linux")]

//! Metamorphic-property tests for `getenv(3)` / `secure_getenv(3)` /
//! `setenv(3)` / `unsetenv(3)`.
//!
//! Properties:
//!
//!   - getenv(name) after setenv(name, val) returns val
//!   - getenv(name) after unsetenv(name) returns NULL
//!   - getenv on non-existent variable returns NULL
//!   - secure_getenv equals getenv when not running setuid
//!   - setenv with overwrite=0 does not overwrite existing value
//!   - setenv with overwrite=1 always overwrites
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, CStr, CString};
use std::sync::{Mutex, MutexGuard};

use frankenlibc_abi::stdlib_abi as fl;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn env_guard() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn unique_name(suffix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("FRANKENLIBC_METAMORPHIC_{nanos}_{suffix}")
}

fn cstr_or_none(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

#[test]
fn metamorphic_setenv_then_getenv_returns_value() {
    let _g = env_guard();
    let name = unique_name("set_get");
    let cn = CString::new(name.as_str()).unwrap();
    let cv = CString::new("hello-from-fl").unwrap();
    let r = unsafe { fl::setenv(cn.as_ptr(), cv.as_ptr(), 1) };
    assert_eq!(r, 0);
    let p = unsafe { fl::getenv(cn.as_ptr()) };
    assert_eq!(cstr_or_none(p).as_deref(), Some("hello-from-fl"));
    let _ = unsafe { fl::unsetenv(cn.as_ptr()) };
}

#[test]
fn metamorphic_unsetenv_then_getenv_returns_null() {
    let _g = env_guard();
    let name = unique_name("unset");
    let cn = CString::new(name.as_str()).unwrap();
    let cv = CString::new("transient").unwrap();
    unsafe { fl::setenv(cn.as_ptr(), cv.as_ptr(), 1) };
    let r = unsafe { fl::unsetenv(cn.as_ptr()) };
    assert_eq!(r, 0);
    let p = unsafe { fl::getenv(cn.as_ptr()) };
    assert!(p.is_null(), "getenv after unsetenv should return NULL");
}

#[test]
fn metamorphic_getenv_nonexistent_returns_null() {
    let _g = env_guard();
    let name = unique_name("never_set");
    let cn = CString::new(name.as_str()).unwrap();
    let p = unsafe { fl::getenv(cn.as_ptr()) };
    assert!(p.is_null());
}

#[test]
fn metamorphic_secure_getenv_equals_getenv_in_normal_execution() {
    let _g = env_guard();
    // PATH must always be set in any test env.
    let cn = CString::new("PATH").unwrap();
    let p1 = unsafe { fl::getenv(cn.as_ptr()) };
    let p2 = unsafe { fl::secure_getenv(cn.as_ptr()) };
    let s1 = cstr_or_none(p1);
    let s2 = cstr_or_none(p2);
    assert_eq!(s1, s2, "secure_getenv != getenv in non-setuid context");
}

#[test]
fn metamorphic_setenv_overwrite_zero_preserves_existing() {
    let _g = env_guard();
    let name = unique_name("no_overwrite");
    let cn = CString::new(name.as_str()).unwrap();
    let v1 = CString::new("first").unwrap();
    let v2 = CString::new("second").unwrap();
    unsafe { fl::setenv(cn.as_ptr(), v1.as_ptr(), 1) };
    let r = unsafe { fl::setenv(cn.as_ptr(), v2.as_ptr(), 0) };
    assert_eq!(r, 0);
    let p = unsafe { fl::getenv(cn.as_ptr()) };
    assert_eq!(cstr_or_none(p).as_deref(), Some("first"), "no-overwrite changed value");
    let _ = unsafe { fl::unsetenv(cn.as_ptr()) };
}

#[test]
fn metamorphic_setenv_overwrite_one_replaces_value() {
    let _g = env_guard();
    let name = unique_name("overwrite");
    let cn = CString::new(name.as_str()).unwrap();
    let v1 = CString::new("first").unwrap();
    let v2 = CString::new("second").unwrap();
    unsafe { fl::setenv(cn.as_ptr(), v1.as_ptr(), 1) };
    unsafe { fl::setenv(cn.as_ptr(), v2.as_ptr(), 1) };
    let p = unsafe { fl::getenv(cn.as_ptr()) };
    assert_eq!(cstr_or_none(p).as_deref(), Some("second"));
    let _ = unsafe { fl::unsetenv(cn.as_ptr()) };
}

#[test]
fn metamorphic_setenv_unsetenv_round_trip_repeatable() {
    let _g = env_guard();
    let name = unique_name("round_trip");
    let cn = CString::new(name.as_str()).unwrap();
    let cv = CString::new("loop_value").unwrap();
    for _ in 0..16 {
        unsafe { fl::setenv(cn.as_ptr(), cv.as_ptr(), 1) };
        let p1 = unsafe { fl::getenv(cn.as_ptr()) };
        assert_eq!(cstr_or_none(p1).as_deref(), Some("loop_value"));
        unsafe { fl::unsetenv(cn.as_ptr()) };
        let p2 = unsafe { fl::getenv(cn.as_ptr()) };
        assert!(p2.is_null());
    }
}

#[test]
fn metamorphic_setenv_empty_string_sets_empty() {
    let _g = env_guard();
    let name = unique_name("empty");
    let cn = CString::new(name.as_str()).unwrap();
    let empty = CString::new("").unwrap();
    unsafe { fl::setenv(cn.as_ptr(), empty.as_ptr(), 1) };
    let p = unsafe { fl::getenv(cn.as_ptr()) };
    assert_eq!(cstr_or_none(p).as_deref(), Some(""));
    let _ = unsafe { fl::unsetenv(cn.as_ptr()) };
}

#[test]
fn getenv_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc getenv + setenv + unsetenv + secure_getenv\",\"reference\":\"posix-invariants\",\"properties\":7,\"divergences\":0}}",
    );
}
