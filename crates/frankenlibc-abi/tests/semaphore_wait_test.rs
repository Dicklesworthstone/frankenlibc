//! C callers exercise semaphore deadlines, token conservation and cancellation.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use frankenlibc_abi::{
    dlfcn_abi as dl, errno_abi, glibc_internal_abi, pthread_abi as p, semaphore_wait as wait,
    unistd_abi as sem,
};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

fn run(name: &CStr, backend: &str) {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fl-sem-wait-{}-{stamp}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("wait.so");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/integration/fixture_semaphore_wait.c");
    let build = Command::new("cc")
        .args(["-shared", "-fPIC", "-O2", "-pthread"])
        .arg(source)
        .arg("-o")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    // The helper's ordinary C runtime is independent; all operations under test
    // are passed as exact function pointers, including the thread lifecycle.
    let open: unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void =
        unsafe { dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ()) };
    let find: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void =
        unsafe { dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ()) };
    let close: unsafe extern "C" fn(*mut c_void) -> c_int =
        unsafe { dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ()) };
    let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let handle = unsafe { open(path.as_ptr(), libc::RTLD_NOW) };
    assert!(!handle.is_null());
    let entries: [(&CStr, *const ()); 14] = [
        (c"sem_init", sem::sem_init as *const ()),
        (c"sem_destroy", sem::sem_destroy as *const ()),
        (
            c"sem_post",
            if backend == "new" {
                wait::post as *const ()
            } else {
                sem::sem_post as *const ()
            },
        ),
        (
            c"sem_wait",
            if backend == "new" {
                wait::wait as *const ()
            } else {
                sem::sem_wait as *const ()
            },
        ),
        (c"sem_trywait", sem::sem_trywait as *const ()),
        (
            c"sem_timedwait",
            if backend == "new" {
                wait::timedwait as *const ()
            } else {
                sem::sem_timedwait as *const ()
            },
        ),
        (
            c"sem_clockwait",
            if backend == "new" {
                wait::clockwait as *const ()
            } else {
                glibc_internal_abi::sem_clockwait as *const ()
            },
        ),
        (c"sem_getvalue", sem::sem_getvalue as *const ()),
        (
            c"__errno_location",
            errno_abi::__errno_location as *const (),
        ),
        (c"pthread_create", p::pthread_create as *const ()),
        (c"pthread_join", p::pthread_join as *const ()),
        (c"pthread_cancel", p::pthread_cancel as *const ()),
        (c"pthread_self", p::pthread_self as *const ()),
        (c"pthread_testcancel", p::pthread_testcancel as *const ()),
    ];
    let table: [*const c_void; 14] = entries.map(|(name, implementation)| {
        if backend == "host" {
            (unsafe { dlsym_oracle::host_addr(name, implementation) }) as *const c_void
        } else {
            implementation.cast()
        }
    });
    // On the gated x86-64 C ABI, each of the 14 struct fields is a pointer.
    // This passes the real API providers, not an alternate semaphore model.
    let function = unsafe { find(handle, name.as_ptr()) };
    assert!(!function.is_null());
    let call: unsafe extern "C" fn(*const *const c_void) -> c_int =
        unsafe { std::mem::transmute(function) };
    let result = unsafe { call(table.as_ptr()) };
    assert_eq!(unsafe { close(handle) }, 0);
    assert_eq!(result, 0, "{name:?}/{backend}: C assertion line");
}
fn isolated(test: &str, protocol: &CStr) {
    if let Ok(backend) = std::env::var("FL_SEM_WAIT_CHILD") {
        run(protocol, &backend);
        return;
    }
    for (backend, mode) in [("host", "strict"), ("new", "strict"), ("new", "hardened")] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("FL_SEM_WAIT_CHILD", backend)
            .env("FRANKENLIBC_MODE", mode)
            .env_remove("LD_PRELOAD")
            .spawn()
            .unwrap();
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{test}/{backend}/{mode}: {status}");
                break;
            }
            if Instant::now() > end {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{test}: timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
#[test]
fn semaphore_deadlines_match_host_without_consuming_invalid_input() {
    isolated(
        "semaphore_deadlines_match_host_without_consuming_invalid_input",
        c"semaphore_deadlines",
    );
}
#[test]
fn semaphore_pending_cancel_preserves_available_tokens() {
    isolated(
        "semaphore_pending_cancel_preserves_available_tokens",
        c"semaphore_pending_cancel",
    );
}
#[test]
fn semaphore_blocked_cancellation_unregisters_waiters() {
    isolated(
        "semaphore_blocked_cancellation_unregisters_waiters",
        c"semaphore_blocked_cancel",
    );
}
#[test]
fn semaphore_overflow_never_publishes_wrapped_state() {
    isolated(
        "semaphore_overflow_never_publishes_wrapped_state",
        c"semaphore_post_overflow_never_changes_state",
    );
}
