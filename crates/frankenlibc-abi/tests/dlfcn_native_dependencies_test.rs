//! Executed C DSOs, not loader-plan assertions. Every successful open must be
//! a native registry handle; accidentally delegating to glibc fails the test.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{
    dlclose, dlerror, dlopen, dlsym, native_dso_handle_for_tests,
};

static TEST_GUARD: Mutex<()> = Mutex::new(());

fn fixture_dir() -> PathBuf {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!(
        "frankenlibc-dependency-group-{}-{stamp}", std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn compile(dir: &Path, name: &str, code: &str, dependencies: &[&Path]) -> PathBuf {
    let source = dir.join(format!("{name}.c"));
    let output = dir.join(format!("lib{name}.so"));
    std::fs::write(&source, code).unwrap();
    let mut command = Command::new("cc");
    command.args(["-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=none", "-Wl,--no-as-needed"])
        .arg("-Xlinker").arg("-soname").arg("-Xlinker").arg(&output)
        .arg("-o").arg(&output).arg(&source);
    for dependency in dependencies {
        command.arg(dependency);
    }
    let result = command.output().expect("a C compiler is required; this is not a skip");
    assert!(result.status.success(), "C fixture build failed: {}\n{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
    output
}

fn error() -> String {
    // SAFETY: dlerror returns a thread-local NUL-terminated string or NULL.
    let pointer = unsafe { dlerror() };
    if pointer.is_null() {
        "no dlerror".to_owned()
    } else {
        unsafe { CStr::from_ptr(pointer) }.to_string_lossy().into_owned()
    }
}

fn try_open(path: &Path, flags: c_int) -> *mut c_void {
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: live, NUL-terminated path; caller manages the returned handle.
    unsafe { dlopen(name.as_ptr(), flags) }
}

fn open(path: &Path, flags: c_int) -> *mut c_void {
    let handle = try_open(path, flags);
    assert!(native_dso_handle_for_tests(handle), "native load failed: {path:?}: {}", error());
    handle
}

fn call(handle: *mut c_void, name: &str) -> c_int {
    let name = CString::new(name).unwrap();
    // SAFETY: all fixture symbols used here have the signature int(void), and
    // the caller retains a native handle for the duration of this call.
    let address = unsafe { dlsym(handle, name.as_ptr()) };
    assert!(!address.is_null(), "fixture lookup failed: {}", error());
    let function: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(address) };
    unsafe { function() }
}

fn close(handle: *mut c_void) {
    // SAFETY: the caller owns exactly one open reference and no call is active.
    assert_eq!(unsafe { dlclose(handle) }, 0, "native close failed: {}", error());
}

#[test]
fn native_loads_transitive_dependencies_and_exports_their_symbols() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = fixture_dir();
    let leaf = compile(&dir, "leaf", "int group_leaf(void) { return 40; }", &[]);
    let middle = compile(&dir, "middle",
        "extern int group_leaf(void); int group_middle(void) { return group_leaf() + 1; }", &[&leaf]);
    let root = compile(&dir, "root",
        "extern int group_middle(void); int group_answer(void) { return group_middle() + 1; }", &[&middle]);
    let handle = open(&root, libc::RTLD_NOW | libc::RTLD_LOCAL);
    assert_eq!(call(handle, "group_answer"), 42);
    assert_eq!(call(handle, "group_leaf"), 40);
    let leaf_handle = open(&leaf, libc::RTLD_NOW | libc::RTLD_NOLOAD);
    close(leaf_handle);
    close(handle);
    assert!(!native_dso_handle_for_tests(handle));
    assert!(!native_dso_handle_for_tests(leaf_handle));
    assert!(try_open(&leaf, libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
}

#[test]
fn native_handle_search_is_breadth_first_across_a_diamond() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = fixture_dir();
    let leaf = compile(&dir, "leaf", "int group_choice(void) { return 10; }", &[]);
    let left = compile(&dir, "left", "int group_left(void) { return 1; }", &[&leaf]);
    let right = compile(&dir, "right", "int group_choice(void) { return 20; }", &[&leaf]);
    let root = compile(&dir, "root", "int group_root(void) { return 0; }", &[&left, &right]);
    let handle = open(&root, libc::RTLD_NOW | libc::RTLD_LOCAL);
    // A depth-first traversal would incorrectly find leaf's 10 before right.
    assert_eq!(call(handle, "group_choice"), 20);
    close(handle);
    for path in [&leaf, &left, &right] {
        assert!(try_open(path, libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
    }
}

#[test]
fn native_shared_dependency_survives_until_its_last_consumer_closes() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = fixture_dir();
    let shared = compile(&dir, "shared", "int group_tick(void) { static int count; return ++count; }", &[]);
    let first = compile(&dir, "first",
        "extern int group_tick(void); int group_first(void) { return group_tick(); }", &[&shared]);
    let second = compile(&dir, "second",
        "extern int group_tick(void); int group_second(void) { return group_tick(); }", &[&shared]);
    let first_handle = open(&first, libc::RTLD_NOW);
    let second_handle = open(&second, libc::RTLD_NOW);
    assert_eq!(call(first_handle, "group_first"), 1);
    assert_eq!(call(second_handle, "group_second"), 2);
    let shared_handle = open(&shared, libc::RTLD_NOW | libc::RTLD_NOLOAD);
    close(shared_handle);
    close(first_handle);
    assert!(native_dso_handle_for_tests(shared_handle));
    assert_eq!(call(second_handle, "group_second"), 3);
    close(second_handle);
    assert!(!native_dso_handle_for_tests(shared_handle));
    let reloaded = open(&first, libc::RTLD_NOW);
    assert_eq!(call(reloaded, "group_first"), 1);
    close(reloaded);
}

#[test]
fn native_dependency_cycles_bind_and_are_collected_after_last_close() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = fixture_dir();
    let a_code = "int group_cycle_state = 30; extern int group_cycle_b(void); int group_cycle_answer(void) { return group_cycle_b(); }";
    let a = compile(&dir, "a", a_code, &[]);
    let b = compile(&dir, "b",
        "extern int group_cycle_state; int group_cycle_b(void) { return group_cycle_state + 12; }", &[&a]);
    let a = compile(&dir, "a", a_code, &[&b]);
    let handle = open(&a, libc::RTLD_NOW);
    assert_eq!(call(handle, "group_cycle_answer"), 42);
    let b_handle = open(&b, libc::RTLD_NOW | libc::RTLD_NOLOAD);
    close(handle);
    assert!(native_dso_handle_for_tests(handle));
    assert_eq!(call(b_handle, "group_cycle_answer"), 42);
    close(b_handle);
    assert!(!native_dso_handle_for_tests(handle));
    assert!(!native_dso_handle_for_tests(b_handle));
}

#[test]
fn native_failed_group_does_not_publish_dependencies_or_change_resident_state() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = fixture_dir();
    let healthy = compile(&dir, "healthy",
        "int group_healthy_tick(void) { static int n; return ++n; }", &[]);
    let healthy_handle = open(&healthy, libc::RTLD_NOW | libc::RTLD_GLOBAL);
    assert_eq!(call(healthy_handle, "group_healthy_tick"), 1);
    let leaf = compile(&dir, "leaf", "int group_leaf(void) { return 40; }", &[]);
    let broken = compile(&dir, "broken",
        "extern int group_missing(void); extern int group_healthy_tick(void); int group_broken(void) { return group_healthy_tick() + group_missing(); }", &[&healthy, &leaf]);
    assert!(try_open(&broken, libc::RTLD_NOW).is_null());
    assert_ne!(error(), "no dlerror");
    assert!(try_open(&leaf, libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
    assert_eq!(call(healthy_handle, "group_healthy_tick"), 2);
    close(healthy_handle);
    assert!(!native_dso_handle_for_tests(healthy_handle));
}

#[test]
fn native_missing_or_malformed_dependency_is_not_a_successful_load() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = fixture_dir();
    let leaf = compile(&dir, "leaf", "int group_leaf(void) { return 40; }", &[]);
    let root = compile(&dir, "root", "int group_root(void) { return 0; }", &[&leaf]);
    let saved = dir.join("saved-leaf.so");
    std::fs::rename(&leaf, &saved).unwrap();
    assert!(try_open(&root, libc::RTLD_NOW).is_null());
    std::fs::write(&leaf, b"not an ELF shared object").unwrap();
    assert!(try_open(&root, libc::RTLD_NOW).is_null());
    assert!(try_open(&root, libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
}

#[test]
fn native_concurrent_first_opens_publish_one_dependency_group() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = fixture_dir();
    let leaf = compile(&dir, "leaf", "int group_leaf(void) { return 41; }", &[]);
    let root = compile(&dir, "root",
        "extern int group_leaf(void); int group_answer(void) { return group_leaf() + 1; }", &[&leaf]);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let workers = (0..8).map(|_| {
        let root = root.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            let handle = open(&root, libc::RTLD_NOW);
            assert_eq!(call(handle, "group_answer"), 42);
            handle as usize
        })
    }).collect::<Vec<_>>();
    let handles = workers.into_iter().map(|worker| worker.join().unwrap()).collect::<Vec<_>>();
    assert!(handles.iter().all(|handle| *handle == handles[0]));
    for handle in &handles {
        close(*handle as *mut c_void);
    }
    assert!(!native_dso_handle_for_tests(handles[0] as *mut c_void));
    assert!(try_open(&leaf, libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
}

#[test]
fn native_ifunc_objects_remain_explicitly_unsupported() {
    let _guard = TEST_GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = fixture_dir();
    let object = compile(&dir, "ifunc",
        "static int implementation(void) { return 42; } static void *resolver(void) { return implementation; } int group_ifunc(void) __attribute__((ifunc(\"resolver\")));", &[]);
    // Do not expose the resolver address as though it were the function.
    assert!(try_open(&object, libc::RTLD_NOW).is_null());
    assert_ne!(error(), "no dlerror");
}
