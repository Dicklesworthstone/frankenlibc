//! Actual ELF search paths and calls, with a required native-handle witness.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CString, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use frankenlibc_abi::dlfcn_abi::{dlclose, dlopen, dlsym, native_dso_handle_for_tests};

static GUARD: Mutex<()> = Mutex::new(());

fn directory() -> PathBuf {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("frankenlibc-search-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn compile(dir: &Path, name: &str, code: &str, dependencies: &[&Path], search: Option<(&str, bool)>) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let source = dir.join(format!("{name}.c"));
    let output = dir.join(format!("lib{name}.so"));
    std::fs::write(&source, code).unwrap();
    let mut command = Command::new("cc");
    command.args(["-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=none", "-Wl,--no-as-needed"])
        .arg("-Xlinker").arg("-soname").arg("-Xlinker").arg(output.file_name().unwrap())
        .arg("-o").arg(&output).arg(&source);
    if let Some((path, old_rpath)) = search {
        command.arg(if old_rpath { "-Wl,--disable-new-dtags" } else { "-Wl,--enable-new-dtags" })
            .arg("-Xlinker").arg("-rpath").arg("-Xlinker").arg(path);
    }
    for dependency in dependencies { command.arg(dependency); }
    let result = command.output().expect("C compiler required, never silently skipped");
    assert!(result.status.success(), "C build failed: {}", String::from_utf8_lossy(&result.stderr));
    output
}

fn try_open(path: &Path, flags: c_int) -> *mut c_void {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid C pathname; the caller releases each successful open.
    unsafe { dlopen(path.as_ptr(), flags) }
}

fn check(path: &Path, expected: c_int) {
    let handle = try_open(path, libc::RTLD_NOW);
    assert!(native_dso_handle_for_tests(handle), "not a native load: {path:?}");
    // SAFETY: these fixtures all export int search_answer(void), and the
    // handle is retained until after the function call has returned.
    let address = unsafe { dlsym(handle, c"search_answer".as_ptr()) };
    assert!(!address.is_null());
    let function: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(address) };
    assert_eq!(unsafe { function() }, expected);
    assert_eq!(unsafe { dlclose(handle) }, 0);
}

#[test]
fn native_runpath_origin_resolves_each_direct_dependency() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = directory();
    let leaf = compile(&dir.join("plugins/deep"), "search_leaf", "int search_leaf(void) { return 40; }", &[], None);
    let middle = compile(&dir.join("plugins"), "search_middle",
        "extern int search_leaf(void); int search_middle(void) { return search_leaf() + 1; }", &[&leaf], Some(("${ORIGIN}/deep", false)));
    let root = compile(&dir, "search_root",
        "extern int search_middle(void); int search_answer(void) { return search_middle() + 1; }", &[&middle], Some(("$ORIGIN/plugins", false)));
    check(&root, 42);
    assert!(try_open(&leaf, libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
}

#[test]
fn native_rpath_is_inherited_by_transitive_dependencies() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = directory();
    let leaf = compile(&dir.join("plugins"), "search_leaf", "int search_leaf(void) { return 40; }", &[], None);
    let middle = compile(&dir.join("plugins"), "search_middle",
        "extern int search_leaf(void); int search_middle(void) { return search_leaf() + 1; }", &[&leaf], None);
    let root = compile(&dir, "search_root",
        "extern int search_middle(void); int search_answer(void) { return search_middle() + 1; }", &[&middle], Some(("$ORIGIN/plugins", true)));
    check(&root, 42);
}

#[test]
fn native_runpath_does_not_leak_to_dependency_children() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = directory();
    let leaf = compile(&dir.join("plugins"), "search_leaf", "int search_leaf(void) { return 40; }", &[], None);
    let middle = compile(&dir.join("plugins"), "search_middle",
        "extern int search_leaf(void); int search_middle(void) { return search_leaf() + 1; }", &[&leaf], None);
    let root = compile(&dir, "search_root",
        "extern int search_middle(void); int search_answer(void) { return search_middle() + 1; }", &[&middle], Some(("$ORIGIN/plugins", false)));
    assert!(try_open(&root, libc::RTLD_NOW).is_null());
    assert!(try_open(&middle, libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
}

#[test]
fn native_runpath_search_preserves_order_and_skips_missing_files() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = directory();
    let first = compile(&dir.join("first"), "search_value", "int search_value(void) { return 11; }", &[], None);
    compile(&dir.join("second"), "search_value", "int search_value(void) { return 22; }", &[], None);
    let root = compile(&dir, "search_root",
        "extern int search_value(void); int search_answer(void) { return search_value(); }", &[&first], Some(("$ORIGIN/absent:$ORIGIN/first:$ORIGIN/second", false)));
    check(&root, 11);
}

#[test]
fn native_initial_environment_precedes_runpath_but_not_rpath() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(root) = std::env::var_os("FRANKENLIBC_SEARCH_CHILD_ROOT") {
        let expected = std::env::var("FRANKENLIBC_SEARCH_CHILD_VALUE").unwrap().parse().unwrap();
        check(Path::new(&root), expected);
        return;
    }
    let dir = directory();
    let embedded = compile(&dir.join("embedded"), "search_value", "int search_value(void) { return 11; }", &[], None);
    compile(&dir.join("environment"), "search_value", "int search_value(void) { return 22; }", &[], None);
    for (name, old_rpath, expected) in [("runpath", false, 22), ("rpath", true, 11)] {
        let root = compile(&dir, name,
            "extern int search_value(void); int search_answer(void) { return search_value(); }", &[&embedded], Some(("$ORIGIN/embedded", old_rpath)));
        // Each process receives LD_LIBRARY_PATH before exec. No unsafe set_var
        // in a multi-threaded test process and no mutable-environment shortcut.
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_initial_environment_precedes_runpath_but_not_rpath", "--nocapture"])
            .env("FRANKENLIBC_SEARCH_CHILD_ROOT", &root)
            .env("FRANKENLIBC_SEARCH_CHILD_VALUE", expected.to_string())
            .env("LD_LIBRARY_PATH", dir.join("environment"))
            .output().unwrap();
        assert!(result.status.success(), "child failed: {}\n{}", String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
    }
}

#[test]
fn native_nodelete_keeps_the_searched_dependency_closure_alive() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = directory();
    let leaf = compile(&dir.join("plugins"), "search_leaf", "int search_tick(void) { static int n; return ++n; }", &[], None);
    let root = compile(&dir, "search_root",
        "extern int search_tick(void); int search_answer(void) { return search_tick(); }", &[&leaf], Some(("$ORIGIN/plugins", false)));
    let handle = try_open(&root, libc::RTLD_NOW | libc::RTLD_NODELETE);
    assert!(native_dso_handle_for_tests(handle));
    // SAFETY: owns the open reference; NODELETE preserves the entire closure.
    assert_eq!(unsafe { dlclose(handle) }, 0);
    check(&root, 1);
    check(&root, 2);
    let dependency = try_open(&leaf, libc::RTLD_NOW | libc::RTLD_NOLOAD);
    assert!(native_dso_handle_for_tests(dependency));
    assert_eq!(unsafe { dlclose(dependency) }, 0);
}

#[test]
fn native_origin_uses_the_loaded_name_not_the_symlink_target() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = directory();
    let real = dir.join("real");
    let alias = dir.join("alias");
    let leaf = compile(&real, "search_value", "int search_value(void) { return 11; }", &[], None);
    compile(&alias, "search_value", "int search_value(void) { return 22; }", &[], None);
    let root = compile(&real, "search_root",
        "extern int search_value(void); int search_answer(void) { return search_value(); }", &[&leaf], Some(("$ORIGIN", false)));
    let link = alias.join(root.file_name().unwrap());
    std::os::unix::fs::symlink(&root, &link).unwrap();
    check(&link, 22);
}
