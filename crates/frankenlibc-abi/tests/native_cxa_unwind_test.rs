//! Regression for the native-finalizer portion of bd-rc0923-epic-eeuy4f.6.
//!
//! Exercise the real native queue with foreign C++ exceptions, not Rust panics
//! or a duplicate queue model. The native destructor is a tail-jump bridge:
//! unwinding from the host-loaded C++ callback goes straight into Rust, without
//! assuming the native loader can register arbitrary DSO unwind tables.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{dlclose, dlopen, dlsym, native_dso_handle_for_tests};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

const NATIVE: &str = r#"
extern int __cxa_atexit(void (*)(void *), void *, void *);
extern void __cxa_finalize(void *);
static char owner_token;
void *fixture_register(void) { return (void *)__cxa_atexit; }
void *fixture_finalize(void) { return (void *)__cxa_finalize; }
void *fixture_token(void) { return &owner_token; }
__asm__(".text\n"
        ".globl native_jump\n"
        ".type native_jump,@function\n"
        "native_jump:\n"
        "endbr64\n"
        "jmp *(%rdi)\n"
        ".size native_jump,.-native_jump\n");
"#;

const DRIVER: &str = r#"
using Action = void (*)(void *);
using Register = int (*)(Action, void *, void *);
using Finalize = void (*)(void *);
struct Marker { int value; };
struct Payload {
    Action action; // native_jump branches here without adding an unwind frame
    int id, calls;
    int *order;
    int exception;
    Finalize finish;
    Register add;
    Action bridge;
    void *token;
    Payload *append;
    bool recurse;
};
static void dispatch(void *raw) {
    auto &p = *static_cast<Payload *>(raw);
    ++p.calls;
    *p.order = *p.order * 10 + p.id;
    if (p.append && p.add(p.bridge, p.append, p.token) != 0) throw Marker{-99};
    if (p.recurse) p.finish(p.token);
    if (p.exception) throw Marker{p.exception};
}
// Keep payloads alive while draining even on an assertion failure. A failing
// test must not leave stack pointers in either runtime's termination queue.
struct Drain {
    Finalize finish;
    void *token;
    ~Drain() noexcept {
        for (int i = 0; i != 16; ++i) {
            try { finish(token); return; } catch (...) {}
        }
    }
};
extern "C" int exercise(void *add_address, void *finish_address,
                        void *bridge_address, void *token, int scenario) {
    auto add = reinterpret_cast<Register>(add_address);
    auto finish = reinterpret_cast<Finalize>(finish_address);
    auto bridge = bridge_address ? reinterpret_cast<Action>(bridge_address) : dispatch;
    int order = 0;
    auto make = [&](int id) {
        return Payload{dispatch, id, 0, &order, 0, finish, add, bridge,
                       token, nullptr, false};
    };
    Payload older = make(1), throwing = make(2), newer = make(3), recursive = make(3);
    throwing.exception = 73;
    throwing.append = scenario == 1 ? &newer : nullptr;
    recursive.recurse = true;
    Drain cleanup{finish, token};
    try {
        if (add(bridge, &older, token) || add(bridge, &throwing, token)) return 1;
        if (scenario == 2 && add(bridge, &recursive, token)) return 2;
        int caught = 0;
        try { finish(token); } catch (const Marker &m) { caught = m.value; }
        if (caught != 73 || throwing.calls != 1 || older.calls != 0) return 3;
        if (order != (scenario == 2 ? 32 : 2)) return 4;
        // Re-register after unwinding, or retain a registration made by the
        // throwing callback. Both must run before the older pending entry.
        if (scenario == 0 && add(bridge, &newer, token)) return 5;
        finish(token);
        if (order != (scenario == 2 ? 321 : 231)) return 6;
        if (older.calls != 1 || throwing.calls != 1) return 7;
        if (scenario == 2 ? recursive.calls != 1 : newer.calls != 1) return 8;
        finish(token);
        if (order != (scenario == 2 ? 321 : 231)) return 9;
        return 0;
    } catch (...) { return 10; }
}
"#;

fn compile(directory: &Path, source: &str, cpp: bool, stem: &str) -> PathBuf {
    let input = directory.join(format!("{stem}.{}", if cpp { "cpp" } else { "c" }));
    let output = directory.join(format!("lib{stem}.so"));
    std::fs::write(&input, source).unwrap();
    let mut command = Command::new(if cpp { "c++" } else { "cc" });
    command.args(["-shared", "-fPIC", "-O2", "-Wl,--build-id=none"]);
    if cpp {
        command.args(["-std=c++17", "-fexceptions"]);
    } else {
        command.args(["-nostdlib", "-fno-stack-protector"]);
    }
    let result = command.arg(&input).arg("-o").arg(&output).output().unwrap();
    assert!(
        result.status.success(),
        "fixture compilation failed: {}\n{}",
        result.status,
        String::from_utf8_lossy(&result.stderr)
    );
    output
}

unsafe fn native_getter(handle: *mut c_void, name: &CStr) -> *mut c_void {
    // SAFETY: callers supply fixture getters with the exact signature below.
    let address = unsafe { dlsym(handle, name.as_ptr()) };
    assert!(!address.is_null(), "missing fixture getter {name:?}");
    let get: unsafe extern "C" fn() -> *mut c_void = unsafe { std::mem::transmute(address) };
    unsafe { get() }
}

fn open_native(path: &Path) -> *mut c_void {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: live NUL-terminated fixture pathname.
    let handle = unsafe { dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(
        native_dso_handle_for_tests(handle),
        "fixture must use the native loader"
    );
    handle
}

#[test]
fn native_finalize_catches_cpp_exceptions_in_both_modes() {
    for mode in ["strict", "hardened"] {
        // An abort-on-unwind regression or a leaked operation lock must fail
        // this test, not abort/hang the rest of cargo's integration tests.
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_finalize_unwind_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("FRANKENLIBC_MODE", mode)
            .env("FRANKENLIBC_CXA_UNWIND_WORKER", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "{mode}: finalizer worker timed out: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("validated native C++ finalizer unwinding"),
            "{mode}: worker failed or ran zero cases: {}\n{stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
#[ignore = "run in mode-isolated subprocesses by the parent test"]
fn native_finalize_unwind_worker() {
    assert_eq!(
        std::env::var("FRANKENLIBC_CXA_UNWIND_WORKER").as_deref(),
        Ok("1")
    );
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "franken-cxa-unwind-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let provider_path = compile(&directory, NATIVE, false, "provider");
    let owner_path = directory.join("libowner.so");
    std::fs::copy(&provider_path, &owner_path).unwrap();
    let driver_path = compile(&directory, DRIVER, true, "driver");
    type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
    type Symbol = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
    type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
    type Exercise =
        unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, c_int) -> c_int;

    // SAFETY: each lookup uses the exact ABI. The helper is deliberately
    // host-loaded so libstdc++ and its exception frames belong to the host.
    unsafe {
        let host_open: Open = dlsym_oracle::host_fn(c"dlopen", dlopen as *const ());
        let host_symbol: Symbol = dlsym_oracle::host_fn(c"dlsym", dlsym as *const ());
        let host_close: Close = dlsym_oracle::host_fn(c"dlclose", dlclose as *const ());
        let name = CString::new(driver_path.as_os_str().as_bytes()).unwrap();
        let driver = host_open(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        assert!(!driver.is_null(), "cannot load the C++ exception helper");
        let address = host_symbol(driver, c"exercise".as_ptr());
        assert!(!address.is_null());
        let exercise: Exercise = std::mem::transmute(address);
        for null_token in [false, true] {
            for scenario in 0..3 {
                let provider = open_native(&provider_path);
                let owner = open_native(&owner_path);
                assert_ne!(
                    provider, owner,
                    "owner and callback provider must be distinct"
                );
                let add = native_getter(owner, c"fixture_register");
                let finish = native_getter(owner, c"fixture_finalize");
                let token = if null_token {
                    std::ptr::null_mut()
                } else {
                    native_getter(owner, c"fixture_token")
                };
                let bridge = dlsym(provider, c"native_jump".as_ptr());
                assert!(!add.is_null() && !finish.is_null() && !bridge.is_null());
                if !null_token {
                    // A private non-null token avoids draining the entire
                    // test process's host C++ exit list as an oracle side effect.
                    let mut oracle_token = 0_u8;
                    let host_add = dlsym_oracle::host_addr(c"__cxa_atexit", add.cast());
                    let host_finish = dlsym_oracle::host_addr(c"__cxa_finalize", finish.cast());
                    assert_eq!(
                        exercise(
                            host_add,
                            host_finish,
                            std::ptr::null_mut(),
                            (&raw mut oracle_token).cast(),
                            scenario,
                        ),
                        0,
                        "host scenario {scenario}"
                    );
                }
                assert_eq!(
                    exercise(add, finish, bridge, token, scenario),
                    0,
                    "native scenario {scenario}, null token {null_token}"
                );
                assert_eq!(dlclose(provider), 0);
                if !null_token {
                    assert!(
                        native_dso_handle_for_tests(provider),
                        "owner must retain its callback provider"
                    );
                }
                assert_eq!(dlclose(owner), 0);
                assert!(
                    !native_dso_handle_for_tests(owner),
                    "unwind leaked the owner's call pin"
                );
                assert!(
                    !native_dso_handle_for_tests(provider),
                    "unwind leaked the provider's call pin"
                );
            }
        }
        assert_eq!(host_close(driver), 0);
    }
    println!("validated native C++ finalizer unwinding: 3 host and 6 native cases");
}
