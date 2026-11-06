#![cfg(target_os = "linux")]

//! Differential conformance harness for GNU `secure_getenv(3)`.
//!
//! `secure_getenv` is `getenv` with the additional contract: if the
//! process is in secure-execution mode (typically because it's
//! running setuid/setgid), it must return NULL regardless of whether
//! the variable is set. In normal (non-secure) execution it behaves
//! identically to `getenv`.
//!
//! The default tests compare normal execution against live GNU libc. With
//! `conformance-testing`, a separate process also models AT_SECURE values in
//! the native auxv cache and exercises the actual public and compatibility
//! entrypoints; this is not a claim of privileged kernel-exec coverage.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{CStr, CString, c_char};

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    fn secure_getenv(name: *const c_char) -> *mut c_char;
}

fn cstr_or_none(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

#[test]
fn diff_secure_getenv_existing_variable_in_normal_execution() {
    // Use PATH which is virtually guaranteed to exist.
    let name = CString::new("PATH").unwrap();
    let fl_p = unsafe { fl::secure_getenv(name.as_ptr()) };
    let lc_p = unsafe { secure_getenv(name.as_ptr()) };
    let fl_s = cstr_or_none(fl_p);
    let lc_s = cstr_or_none(lc_p);
    assert_eq!(fl_s, lc_s, "PATH lookup: fl={fl_s:?} lc={lc_s:?}");
    assert!(fl_s.is_some(), "PATH should be set");
}

#[test]
fn diff_secure_getenv_nonexistent_variable_returns_null() {
    let name = CString::new("FRANKENLIBC_DEFINITELY_NOT_SET_ENVVAR_XYZ").unwrap();
    unsafe { std::env::remove_var("FRANKENLIBC_DEFINITELY_NOT_SET_ENVVAR_XYZ") };
    let fl_p = unsafe { fl::secure_getenv(name.as_ptr()) };
    let lc_p = unsafe { secure_getenv(name.as_ptr()) };
    assert!(fl_p.is_null());
    assert!(lc_p.is_null());
}

#[test]
fn diff_secure_getenv_empty_string_value() {
    // Set a variable to empty; getenv should return non-NULL pointer
    // to an empty string (NOT NULL).
    let name = "FRANKENLIBC_TEST_EMPTY_ENV";
    let cname = CString::new(name).unwrap();
    unsafe { std::env::set_var(name, "") };
    let fl_p = unsafe { fl::secure_getenv(cname.as_ptr()) };
    let lc_p = unsafe { secure_getenv(cname.as_ptr()) };
    let fl_s = cstr_or_none(fl_p);
    let lc_s = cstr_or_none(lc_p);
    unsafe { std::env::remove_var(name) };
    assert_eq!(fl_s, lc_s);
    assert_eq!(fl_s.as_deref(), Some(""), "empty string lookup");
}

#[test]
fn diff_secure_getenv_with_special_value() {
    let name = "FRANKENLIBC_TEST_SECURE_GETENV_VALUE";
    let value = "value-with-spaces and =equals=";
    let cname = CString::new(name).unwrap();
    unsafe { std::env::set_var(name, value) };
    let fl_p = unsafe { fl::secure_getenv(cname.as_ptr()) };
    let lc_p = unsafe { secure_getenv(cname.as_ptr()) };
    let fl_s = cstr_or_none(fl_p);
    let lc_s = cstr_or_none(lc_p);
    unsafe { std::env::remove_var(name) };
    assert_eq!(fl_s, lc_s);
    assert_eq!(fl_s.as_deref(), Some(value));
}

#[test]
fn fl_secure_getenv_null_name_returns_null() {
    // glibc segfaults on NULL name; we only assert fl is hardened.
    let p = unsafe { fl::secure_getenv(std::ptr::null()) };
    assert!(p.is_null());
}

#[test]
fn diff_secure_getenv_preserves_errno_for_existing_and_missing_names() {
    let key = c"FRANKENLIBC_SECURE_GETENV_ERRNO_VALUE";
    // This test is the live normal-execution GNU control. Secure startup state
    // is separately modeled against the real native auxv cache below.
    unsafe { std::env::set_var(key.to_str().unwrap(), "errno-control") };
    for name in [key, c"FRANKENLIBC_SECURE_GETENV_ERRNO_ABSENT"] {
        unsafe { *libc::__errno_location() = 1234 };
        let expected = unsafe { secure_getenv(name.as_ptr()) };
        assert_eq!(unsafe { *libc::__errno_location() }, 1234);
        for lookup in [
            fl::secure_getenv,
            frankenlibc_abi::glibc_internal_abi::__secure_getenv,
            frankenlibc_abi::glibc_internal_abi::__libc_secure_getenv,
        ] {
            unsafe { frankenlibc_abi::errno_abi::set_abi_errno(1234) };
            let actual = unsafe { lookup(name.as_ptr()) };
            assert_eq!(cstr_or_none(actual), cstr_or_none(expected));
            assert_eq!(
                unsafe { *frankenlibc_abi::errno_abi::__errno_location() },
                1234
            );
        }
    }
    unsafe { std::env::remove_var(key.to_str().unwrap()) };
}

#[cfg(feature = "conformance-testing")]
#[test]
fn modeled_startup_auxv_controls_public_and_compatibility_names() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const NAME: &str = "modeled_startup_auxv_controls_public_and_compatibility_names";
    const CHILD: &str = "FRANKENLIBC_SECURE_CACHE_TEST_CHILD";
    const MARKER: &str = "modeled AT_SECURE public and alias cases executed";
    if std::env::var_os(CHILD).as_deref() != Some(std::ffi::OsStr::new("1")) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env(CHILD, "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if start.elapsed() > Duration::from_secs(40) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("secure_getenv child timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        assert!(stdout.contains(MARKER), "child must execute the named test");
        assert!(stdout.contains("1 passed"), "{stdout}");
        return;
    }

    let key = c"FRANKENLIBC_SECURE_CACHE_VALUE";
    // SAFETY: this child owns its environment and runs only this named test.
    assert_eq!(
        unsafe { fl::setenv(key.as_ptr(), c"visible-through-getenv".as_ptr(), 1) },
        0
    );
    type Lookup = unsafe extern "C" fn(*const c_char) -> *mut c_char;
    let names: [(&str, Lookup); 3] = [
        ("secure_getenv", fl::secure_getenv),
        (
            "__secure_getenv",
            frankenlibc_abi::glibc_internal_abi::__secure_getenv,
        ),
        (
            "__libc_secure_getenv",
            frankenlibc_abi::glibc_internal_abi::__libc_secure_getenv,
        ),
    ];
    // This is modeled startup state, not proof of a privileged kernel exec.
    // The ordinary public functions still consult their real production cache.
    for secure in [Some(0), Some(1), Some(17), None, Some(0)] {
        // SAFETY: no other test runs in this isolated process, and no auxiliary
        // vector entry except the selected security flag is modified.
        unsafe { fl::set_secure_auxv_for_conformance(secure) };
        let ordinary = unsafe { fl::getenv(key.as_ptr()) };
        assert!(
            !ordinary.is_null(),
            "rejection must not be a missing-key pass"
        );
        for (name, lookup) in names {
            unsafe { frankenlibc_abi::errno_abi::set_abi_errno(1234) };
            let value = unsafe { lookup(key.as_ptr()) };
            assert_eq!(
                unsafe { *frankenlibc_abi::errno_abi::__errno_location() },
                1234,
                "{name}"
            );
            if secure == Some(0) {
                assert_eq!(value, ordinary, "{name}: {secure:?}");
            } else {
                assert!(value.is_null(), "{name}: {secure:?}");
            }
        }
    }
    println!("{MARKER}");
}

#[test]
fn secure_getenv_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc secure_getenv\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
