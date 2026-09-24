//! Real ELF regressions for the standalone loader's public ABI.
//!
//! Each scenario runs in a fresh process: the loader intentionally snapshots
//! the initial LD_LIBRARY_PATH rather than observing later environment edits.
//! A host-loader handle is always a test failure, even when symbol lookup works.
#![cfg(all(feature = "standalone", target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_int, c_void};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{
    dlclose, dlerror, dlopen, dlsym, dlvsym, native_dso_handle_for_tests,
};

const NAME: &str = "libfranken_standalone_fixture.so";
const DEPENDENCY: &str = "libfranken_standalone_dependency.so";
const CHILD: &str = "FRANKEN_STANDALONE_LOADER_CASE";
const DIRECTORY: &str = "FRANKEN_STANDALONE_LOADER_DIRECTORY";
static FINALIZED: AtomicI32 = AtomicI32::new(0);
static EXIT_MARKER: OnceLock<PathBuf> = OnceLock::new();

const DEPENDENCY_C: &str = "int fixture_dependency(void) { return 7; }\n";
const FIXTURE_C: &str = r#"
extern int fixture_dependency(void);
static int initializations;
static void (*recorder)(int);
__attribute__((constructor)) static void initialize(void) {
    initializations += 1;
}
__attribute__((destructor)) static void finalize(void) {
    if (recorder) recorder(23);
}
int fixture_value(void) { return FIXTURE_VALUE + fixture_dependency(); }
int fixture_initializations(void) { return initializations; }
void fixture_set_recorder(void (*callback)(int)) { recorder = callback; }
"#;

fn command_ok(command: &mut Command) {
    let output = command.output().expect("execute fixture command");
    assert!(
        output.status.success(),
        "command {command:?} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn compiler() -> Command {
    let mut command = Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()));
    command.args([
        "-shared", "-fPIC", "-nostdlib", "-fno-stack-protector",
        "-Wl,--hash-style=both", "-Wl,-z,now", "-Wl,-z,relro",
    ]);
    command
}

fn build_fixtures(root: &Path) {
    fs::create_dir_all(root.join("search")).unwrap();
    fs::create_dir_all(root.join("cwd")).unwrap();
    fs::write(root.join("dependency.c"), DEPENDENCY_C).unwrap();
    fs::write(root.join("fixture.c"), FIXTURE_C).unwrap();
    fs::write(
        root.join("versions.map"),
        "FRANKEN_TEST_1 { global: fixture_*; local: *; };\n",
    ).unwrap();
    command_ok(compiler()
        .arg(root.join("dependency.c"))
        .arg(format!("-Wl,-soname,{DEPENDENCY}"))
        .arg("-o").arg(root.join("search").join(DEPENDENCY)));
    for (directory, value) in [("search", "35"), ("cwd", "6")] {
        command_ok(compiler()
            .arg(root.join("fixture.c"))
            .arg(format!("-DFIXTURE_VALUE={value}"))
            .arg(format!("-Wl,-soname,{NAME}"))
            .arg(format!("-Wl,--version-script={}", root.join("versions.map").display()))
            .arg("-Wl,-rpath,$ORIGIN")
            .arg("-L").arg(root.join("search"))
            .arg("-lfranken_standalone_dependency")
            .arg("-o").arg(root.join(directory).join(NAME)));
    }
}

fn error_text() -> String {
    // SAFETY: dlerror owns a NUL-terminated message until the next loader call.
    let error = unsafe { dlerror() };
    if error.is_null() {
        "<no loader error>".into()
    } else {
        unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned()
    }
}

fn open_name(name: &CStr, flags: c_int) -> *mut c_void {
    // SAFETY: name is NUL terminated and lives through the call.
    let handle = unsafe { dlopen(name.as_ptr(), flags) };
    assert!(!handle.is_null(), "native load failed: {}", error_text());
    assert!(native_dso_handle_for_tests(handle), "host fallback is not native loading");
    handle
}

fn open_path(path: &Path, flags: c_int) -> *mut c_void {
    open_name(&CString::new(path.as_os_str().as_bytes()).unwrap(), flags)
}

fn integer_symbol(handle: *mut c_void, name: &CStr) -> c_int {
    // SAFETY: callers retain a live handle; fixtures export this exact ABI.
    let address = unsafe { dlsym(handle, name.as_ptr()) };
    assert!(!address.is_null(), "lookup failed: {}", error_text());
    let function: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(address) };
    unsafe { function() }
}

unsafe extern "C" fn record_finalizer(value: c_int) {
    FINALIZED.store(value, Ordering::SeqCst);
    if let Some(path) = EXIT_MARKER.get() {
        // Never unwind through a foreign finalizer. The parent checks the file.
        let _ = fs::write(path, value.to_string());
    }
}

fn install_recorder(handle: *mut c_void) {
    // SAFETY: a live fixture exports this exact callback registration ABI.
    let address = unsafe { dlsym(handle, c"fixture_set_recorder".as_ptr()) };
    assert!(!address.is_null(), "recorder lookup failed: {}", error_text());
    let function: unsafe extern "C" fn(unsafe extern "C" fn(c_int)) =
        unsafe { std::mem::transmute(address) };
    unsafe { function(record_finalizer) };
}

fn close(handle: *mut c_void) {
    // SAFETY: caller owns an outstanding dlopen reference to the handle.
    assert_eq!(unsafe { dlclose(handle) }, 0, "close failed: {}", error_text());
}

fn expect_lookup_failure(handle: *mut c_void, name: &CStr) {
    // SAFETY: name is valid; the API must reject stale handles without access.
    assert!(unsafe { dlsym(handle, name.as_ptr()) }.is_null());
    assert!(!unsafe { dlerror() }.is_null());
    assert!(unsafe { dlerror() }.is_null(), "dlerror must be consumed once");
}

fn run_child(case: &str, root: &Path) {
    let path = root.join("search").join(NAME);
    match case {
        "path" => {
            let handle = open_path(&path, libc::RTLD_NOW);
            assert_eq!(integer_symbol(handle, c"fixture_value"), 42);
            assert_eq!(integer_symbol(handle, c"fixture_initializations"), 1);
            install_recorder(handle);
            let again = open_path(&path, libc::RTLD_NOW);
            assert_eq!(handle, again);
            close(handle);
            assert_eq!(FINALIZED.load(Ordering::SeqCst), 0);
            assert_eq!(integer_symbol(again, c"fixture_initializations"), 1);
            close(again);
            assert_eq!(FINALIZED.load(Ordering::SeqCst), 23);
            expect_lookup_failure(again, c"fixture_value");
            assert_eq!(unsafe { dlclose(again) }, -1);
        }
        "versions" => {
            let handle = open_path(&path, libc::RTLD_NOW);
            let address = unsafe { dlvsym(handle, c"fixture_value".as_ptr(), c"FRANKEN_TEST_1".as_ptr()) };
            assert!(!address.is_null(), "native version lookup failed: {}", error_text());
            let function: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(address) };
            assert_eq!(unsafe { function() }, 42);
            assert!(unsafe { dlvsym(handle, c"fixture_value".as_ptr(), c"MISSING_VERSION".as_ptr()) }.is_null());
            assert!(!unsafe { dlerror() }.is_null());
            expect_lookup_failure(handle, c"missing_symbol");
            close(handle);
        }
        "invalid" => {
            assert!(unsafe { dlopen(std::ptr::null(), 0) }.is_null());
            assert!(!unsafe { dlerror() }.is_null());
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert!(unsafe { dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) }.is_null());
            // A no-load miss need not create a pending diagnostic.
            let _ = unsafe { dlerror() };
            let handle = open_name(&path, libc::RTLD_NOW);
            assert_eq!(integer_symbol(handle, c"fixture_initializations"), 1);
            close(handle);
            let bad = root.join("invalid.so");
            fs::write(&bad, b"not an ELF shared object\n").unwrap();
            let bad = CString::new(bad.as_os_str().as_bytes()).unwrap();
            assert!(unsafe { dlopen(bad.as_ptr(), libc::RTLD_NOW) }.is_null());
            assert!(!unsafe { dlerror() }.is_null());
            assert_eq!(unsafe { dlclose(std::ptr::null_mut()) }, -1);
        }
        "nodelete" => {
            let handle = open_path(&path, libc::RTLD_NOW | libc::RTLD_NODELETE);
            install_recorder(handle);
            close(handle);
            assert_eq!(FINALIZED.load(Ordering::SeqCst), 0);
            let again = open_path(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD);
            assert_eq!(handle, again);
            assert_eq!(integer_symbol(again, c"fixture_initializations"), 1);
            close(again);
            assert_eq!(FINALIZED.load(Ordering::SeqCst), 0);
        }
        "shutdown" => {
            EXIT_MARKER.set(root.join("finalized")).unwrap();
            let handle = open_path(&path, libc::RTLD_NOW);
            install_recorder(handle);
            // Exercise the owned libc exit chain, not Rust's host termination.
            unsafe { frankenlibc_abi::stdlib_abi::exit(37) };
        }
        "name" => {
            // A same-named cwd DSO returns 13. The initial search path wins.
            let handle = open_name(&CString::new(NAME).unwrap(), libc::RTLD_NOW);
            assert_eq!(integer_symbol(handle, c"fixture_value"), 42);
            close(handle);
            let explicit = open_path(&root.join("cwd").join(NAME), libc::RTLD_NOW);
            assert_eq!(integer_symbol(explicit, c"fixture_value"), 13);
            close(explicit);
        }
        "resident_name" => {
            let name = CString::new(NAME).unwrap();
            assert!(unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) }.is_null());
            let _ = unsafe { dlerror() };
            let handle = open_path(&path, libc::RTLD_NOW);
            install_recorder(handle);
            fs::rename(&path, root.join("original.so")).unwrap();
            let again = open_name(&name, libc::RTLD_NOW | libc::RTLD_NOLOAD);
            assert_eq!(handle, again, "SONAME must retain the original loaded image");
            assert_eq!(integer_symbol(again, c"fixture_value"), 42);
            assert_eq!(integer_symbol(again, c"fixture_initializations"), 1);
            close(handle);
            assert_eq!(FINALIZED.load(Ordering::SeqCst), 0);
            close(again);
            assert_eq!(FINALIZED.load(Ordering::SeqCst), 23);
            assert!(unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) }.is_null());
        }
        "no_implicit_cwd" => {
            let name = CString::new(NAME).unwrap();
            assert!(root.join("cwd").join(NAME).is_file());
            assert!(unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW) }.is_null());
            assert!(!unsafe { dlerror() }.is_null());
        }
        _ => panic!("unknown loader scenario: {case}"),
    }
}

#[test]
fn standalone_native_loader_regressions() {
    if let Ok(case) = std::env::var(CHILD) {
        let root = PathBuf::from(std::env::var_os(DIRECTORY).expect("child directory"));
        run_child(&case, &root);
        return;
    }
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let root = std::env::temp_dir().join(format!("franken-standalone-loader-{}-{nonce}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&root).expect("fresh private fixture directory");
    eprintln!("standalone loader fixtures: {}", root.display());
    let template = root.join("template");
    build_fixtures(&template);
    for mode in ["strict", "hardened"] {
        for case in ["path", "versions", "invalid", "nodelete", "shutdown", "name", "resident_name", "no_implicit_cwd"] {
            let directory = root.join(mode).join(case);
            for subdirectory in ["search", "cwd", "empty"] {
                fs::create_dir_all(directory.join(subdirectory)).unwrap();
            }
            for (subdirectory, name) in [("search", NAME), ("search", DEPENDENCY), ("cwd", NAME)] {
                fs::copy(template.join(subdirectory).join(name), directory.join(subdirectory).join(name)).unwrap();
            }
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "standalone_native_loader_regressions", "--nocapture"])
                .env(CHILD, case).env(DIRECTORY, &directory)
                .env("FRANKENLIBC_MODE", mode)
                .env("LD_LIBRARY_PATH", directory.join(if matches!(case, "path" | "no_implicit_cwd") { "empty" } else { "search" }))
                .current_dir(directory.join("cwd"))
                .output().expect("execute isolated loader scenario");
            let expected = if case == "shutdown" { 37 } else { 0 };
            assert_eq!(output.status.code(), Some(expected), "{mode}/{case}: {}\n{}",
                String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            if case == "shutdown" {
                assert_eq!(fs::read_to_string(directory.join("finalized")).unwrap(), "23");
            }
        }
    }
}
