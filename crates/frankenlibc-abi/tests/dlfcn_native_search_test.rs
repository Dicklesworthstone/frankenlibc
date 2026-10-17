//! Actual ELF search paths and calls, with a required native-handle witness.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use frankenlibc_abi::dlfcn_abi::{dlclose, dlopen, dlsym, native_dso_handle_for_tests};
use std::ffi::{CStr, CString, OsStr, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static GUARD: Mutex<()> = Mutex::new(());

fn directory() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("frankenlibc-search-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn compile(
    dir: &Path,
    name: &str,
    code: &str,
    dependencies: &[&Path],
    search: Option<(&str, bool)>,
) -> PathBuf {
    compile_with_soname(dir, name, code, dependencies, search, None)
}

fn compile_with_soname(
    dir: &Path,
    name: &str,
    code: &str,
    dependencies: &[&Path],
    search: Option<(&str, bool)>,
    soname: Option<&str>,
) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let source = dir.join(format!("{name}.c"));
    let output = dir.join(format!("lib{name}.so"));
    std::fs::write(&source, code).unwrap();
    let mut command = Command::new("cc");
    command
        .args([
            "-shared",
            "-fPIC",
            "-nostdlib",
            "-Wl,--build-id=none",
            "-Wl,--no-as-needed",
        ])
        .arg("-Xlinker")
        .arg("-soname")
        .arg("-Xlinker")
        .arg(
            soname
                .map(OsStr::new)
                .unwrap_or(output.file_name().unwrap()),
        )
        .arg("-o")
        .arg(&output)
        .arg(&source);
    if let Some((path, old_rpath)) = search {
        command
            .arg(if old_rpath {
                "-Wl,--disable-new-dtags"
            } else {
                "-Wl,--enable-new-dtags"
            })
            .arg("-Xlinker")
            .arg("-rpath")
            .arg("-Xlinker")
            .arg(path);
    }
    for dependency in dependencies {
        command.arg(dependency);
    }
    let result = command
        .output()
        .expect("C compiler required, never silently skipped");
    assert!(
        result.status.success(),
        "C build failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    output
}

fn try_open(path: &Path, flags: c_int) -> *mut c_void {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid C pathname; the caller releases each successful open.
    unsafe { dlopen(path.as_ptr(), flags) }
}

fn check(path: &Path, expected: c_int) {
    let handle = try_open(path, libc::RTLD_NOW);
    assert!(
        native_dso_handle_for_tests(handle),
        "not a native load: {path:?}"
    );
    // SAFETY: these fixtures all export int search_answer(void), and the
    // handle is retained until after the function call has returned.
    let address = unsafe { dlsym(handle, c"search_answer".as_ptr()) };
    assert!(!address.is_null());
    let function: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(address) };
    assert_eq!(unsafe { function() }, expected);
    assert_eq!(unsafe { dlclose(handle) }, 0);
}

/// GNU documents these --list-diagnostics fields as the actual host LIB and
/// PLATFORM expansions. The candidate follows kernel AT_PLATFORM explicitly,
/// so host CPU aliases are reported separately rather than assumed identical.
fn host_dynamic_tokens() -> (String, String) {
    let loader = [
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "/usr/lib64/ld-linux-x86-64.so.2",
    ]
    .into_iter()
    .find(|path| Path::new(path).is_file())
    .expect("the host GNU loader is required, never silently skipped");
    let output = Command::new(loader)
        .arg("--list-diagnostics")
        .output()
        .unwrap();
    assert!(output.status.success());
    let diagnostics = String::from_utf8(output.stdout).unwrap();
    let value = |field: &str| {
        let value = diagnostics
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .and_then(|value| value.strip_prefix('"'))
            .and_then(|value| value.strip_suffix('"'))
            .expect("host diagnostics must expose the dynamic token");
        assert!(
            !value.is_empty()
                && Path::new(value)
                    .components()
                    .all(|component| matches!(component, std::path::Component::Normal(_))),
            "expected a relative native token value: {value:?}"
        );
        value.to_owned()
    };
    (value("dl_dst_lib="), value("dl_platform="))
}

fn check_host(path: &Path, expected: c_int) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: the direct libc symbol is the host oracle in debug integration
    // tests. The tagged-handle assertion detects accidental native capture.
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW) };
    if handle.is_null() {
        // SAFETY: dlerror returns either NULL or its own terminated message.
        let error = unsafe { libc::dlerror() };
        let error = if error.is_null() {
            "no dlerror message".into()
        } else {
            unsafe { CStr::from_ptr(error) }.to_string_lossy()
        };
        panic!("host load failed for {path:?}: {error}");
    }
    assert!(!native_dso_handle_for_tests(handle), "host oracle captured");
    // SAFETY: every fixture exports this exact function signature, and the
    // handle is retained until its function call finishes.
    let address = unsafe { libc::dlsym(handle, c"search_answer".as_ptr()) };
    assert!(!address.is_null());
    let function: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(address) };
    assert_eq!(unsafe { function() }, expected);
    assert_eq!(unsafe { libc::dlclose(handle) }, 0);
}

#[test]
fn native_lib_tokens_match_host_for_runpath_and_rpath() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let (library, _) = host_dynamic_tokens();
    for (index, (search, old_rpath)) in [
        ("$ORIGIN/$LIB", false),
        ("${ORIGIN}/${LIB}", false),
        ("$ORIGIN/${LIB}", true),
        ("${ORIGIN}/$LIB", true),
    ]
    .into_iter()
    .enumerate()
    {
        let dir = directory();
        let leaf = compile(
            &dir.join(&library),
            &format!("token_leaf_{index}"),
            "int token_leaf(void) { return 41; }",
            &[],
            None,
        );
        let root = compile(
            &dir,
            &format!("token_root_{index}"),
            "extern int token_leaf(void); int search_answer(void) { return token_leaf() + 1; }",
            &[&leaf],
            Some((search, old_rpath)),
        );
        check_host(&root, 42);
        check(&root, 42);
        assert!(try_open(&leaf, libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
    }
}

#[test]
fn native_dlopen_expands_lib_and_preserves_unknown_literal_names() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let (library, _) = host_dynamic_tokens();
    let dir = directory();
    let object = compile(
        &dir.join(&library),
        "token_entry",
        "int search_answer(void) { return 73; }",
        &[],
        None,
    );
    for token_path in ["$LIB", "${LIB}"] {
        let path = dir.join(token_path).join(object.file_name().unwrap());
        check_host(&path, 73);
        check(&path, 73);
    }
    let literal = compile(
        &dir.join("$ORIGIN_EXTRA/$LIB1/${LIB_EXTRA}/${PLATFORM/literal$"),
        "token_literal",
        "int search_answer(void) { return 89; }",
        &[],
        None,
    );
    check_host(&literal, 89);
    check(&literal, 89);
}

#[test]
fn native_needed_lib_token_expands_using_the_referencing_object() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let (library, _) = host_dynamic_tokens();
    let dir = directory();
    let leaf = compile_with_soname(
        &dir.join(library),
        "token_needed_leaf",
        "int token_needed_leaf(void) { return 54; }",
        &[],
        None,
        Some("$ORIGIN/${LIB}/libtoken_needed_leaf.so"),
    );
    let root = compile(
        &dir,
        "token_needed_root",
        "extern int token_needed_leaf(void); int search_answer(void) { return token_needed_leaf(); }",
        &[&leaf],
        None,
    );
    check_host(&root, 54);
    check(&root, 54);
}

#[test]
fn native_initial_environment_expands_lib_like_host() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(root) = std::env::var_os("FRANKENLIBC_TOKEN_CHILD_ROOT") {
        check_host(Path::new(&root), 65);
        check(Path::new(&root), 65);
        return;
    }
    let (library, _) = host_dynamic_tokens();
    let dir = directory();
    let leaf = compile(
        &dir.join(library),
        "token_environment_leaf",
        "int token_environment_leaf(void) { return 65; }",
        &[],
        None,
    );
    let root = compile(
        &dir,
        "token_environment_root",
        "extern int token_environment_leaf(void); int search_answer(void) { return token_environment_leaf(); }",
        &[&leaf],
        None,
    );
    // Both loaders receive the same initial environment before exec. The host
    // closes its complete group before the native ownership check runs.
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_initial_environment_expands_lib_like_host",
            "--nocapture",
        ])
        .env("FRANKENLIBC_TOKEN_CHILD_ROOT", &root)
        .env("LD_LIBRARY_PATH", dir.join("${LIB}"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "token child failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn native_platform_tokens_follow_kernel_auxv() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(root) = std::env::var_os("FRANKENLIBC_PLATFORM_CHILD_ROOT") {
        check(Path::new(&root), 73);
        return;
    }
    // SAFETY: the host getauxval oracle returns the kernel's process-lifetime
    // terminated string. This is independent of the candidate's procfs reader.
    let address = unsafe { libc::getauxval(libc::AT_PLATFORM) } as *const libc::c_char;
    assert!(!address.is_null(), "Linux x86-64 must supply AT_PLATFORM");
    let platform = unsafe { CStr::from_ptr(address) }.to_str().unwrap();
    assert!(
        !platform.is_empty()
            && Path::new(platform)
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
    );
    let (_, host_platform) = host_dynamic_tokens();
    if host_platform != platform {
        eprintln!(
            "PLATFORM scope: kernel={platform}, GNU loader={host_platform}; CPU aliases are not emulated"
        );
    }
    let dir = directory();
    let leaf = compile(
        &dir.join(platform),
        "token_platform_leaf",
        "int platform_leaf(void) { return 73; } int search_answer(void) { return 73; }",
        &[],
        None,
    );
    for token in ["$PLATFORM", "${PLATFORM}"] {
        check(&dir.join(token).join(leaf.file_name().unwrap()), 73);
    }
    for (name, old_rpath) in [("platform_runpath", false), ("platform_rpath", true)] {
        let root = compile(
            &dir,
            name,
            "extern int platform_leaf(void); int search_answer(void) { return platform_leaf(); }",
            &[&leaf],
            Some(("$ORIGIN/${PLATFORM}", old_rpath)),
        );
        check(&root, 73);
    }
    let needed_leaf = compile_with_soname(
        &dir.join(platform),
        "token_platform_needed",
        "int platform_needed(void) { return 44; }",
        &[],
        None,
        Some("$ORIGIN/${PLATFORM}/libtoken_platform_needed.so"),
    );
    let needed_root = compile(
        &dir,
        "token_platform_needed_root",
        "extern int platform_needed(void); int search_answer(void) { return platform_needed(); }",
        &[&needed_leaf],
        None,
    );
    check(&needed_root, 44);
    let environment_root = compile(
        &dir,
        "token_platform_environment",
        "extern int platform_leaf(void); int search_answer(void) { return platform_leaf(); }",
        &[&leaf],
        None,
    );
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_platform_tokens_follow_kernel_auxv",
            "--nocapture",
        ])
        .env("FRANKENLIBC_PLATFORM_CHILD_ROOT", &environment_root)
        .env("LD_LIBRARY_PATH", dir.join("$PLATFORM"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "PLATFORM child failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn native_runpath_origin_resolves_each_direct_dependency() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = directory();
    let leaf = compile(
        &dir.join("plugins/deep"),
        "search_leaf",
        "int search_leaf(void) { return 40; }",
        &[],
        None,
    );
    let middle = compile(
        &dir.join("plugins"),
        "search_middle",
        "extern int search_leaf(void); int search_middle(void) { return search_leaf() + 1; }",
        &[&leaf],
        Some(("${ORIGIN}/deep", false)),
    );
    let root = compile(
        &dir,
        "search_root",
        "extern int search_middle(void); int search_answer(void) { return search_middle() + 1; }",
        &[&middle],
        Some(("$ORIGIN/plugins", false)),
    );
    check(&root, 42);
    assert!(try_open(&leaf, libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
}

#[test]
fn native_rpath_is_inherited_by_transitive_dependencies() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = directory();
    let leaf = compile(
        &dir.join("plugins"),
        "search_leaf",
        "int search_leaf(void) { return 40; }",
        &[],
        None,
    );
    let middle = compile(
        &dir.join("plugins"),
        "search_middle",
        "extern int search_leaf(void); int search_middle(void) { return search_leaf() + 1; }",
        &[&leaf],
        None,
    );
    let root = compile(
        &dir,
        "search_root",
        "extern int search_middle(void); int search_answer(void) { return search_middle() + 1; }",
        &[&middle],
        Some(("$ORIGIN/plugins", true)),
    );
    check(&root, 42);
}

#[test]
fn native_runpath_does_not_leak_to_dependency_children() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = directory();
    let leaf = compile(
        &dir.join("plugins"),
        "search_leaf",
        "int search_leaf(void) { return 40; }",
        &[],
        None,
    );
    let middle = compile(
        &dir.join("plugins"),
        "search_middle",
        "extern int search_leaf(void); int search_middle(void) { return search_leaf() + 1; }",
        &[&leaf],
        None,
    );
    let root = compile(
        &dir,
        "search_root",
        "extern int search_middle(void); int search_answer(void) { return search_middle() + 1; }",
        &[&middle],
        Some(("$ORIGIN/plugins", false)),
    );
    assert!(try_open(&root, libc::RTLD_NOW).is_null());
    assert!(try_open(&middle, libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
}

#[test]
fn native_runpath_search_preserves_order_and_skips_missing_files() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = directory();
    let first = compile(
        &dir.join("first"),
        "search_value",
        "int search_value(void) { return 11; }",
        &[],
        None,
    );
    compile(
        &dir.join("second"),
        "search_value",
        "int search_value(void) { return 22; }",
        &[],
        None,
    );
    let root = compile(
        &dir,
        "search_root",
        "extern int search_value(void); int search_answer(void) { return search_value(); }",
        &[&first],
        Some(("$ORIGIN/absent:$ORIGIN/first:$ORIGIN/second", false)),
    );
    check(&root, 11);
}

#[test]
fn native_initial_environment_precedes_runpath_but_not_rpath() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(root) = std::env::var_os("FRANKENLIBC_SEARCH_CHILD_ROOT") {
        let expected = std::env::var("FRANKENLIBC_SEARCH_CHILD_VALUE")
            .unwrap()
            .parse()
            .unwrap();
        check(Path::new(&root), expected);
        return;
    }
    let dir = directory();
    let embedded = compile(
        &dir.join("embedded"),
        "search_value",
        "int search_value(void) { return 11; }",
        &[],
        None,
    );
    compile(
        &dir.join("environment"),
        "search_value",
        "int search_value(void) { return 22; }",
        &[],
        None,
    );
    for (name, old_rpath, expected) in [("runpath", false, 22), ("rpath", true, 11)] {
        let root = compile(
            &dir,
            name,
            "extern int search_value(void); int search_answer(void) { return search_value(); }",
            &[&embedded],
            Some(("$ORIGIN/embedded", old_rpath)),
        );
        // Each process receives LD_LIBRARY_PATH before exec. No unsafe set_var
        // in a multi-threaded test process and no mutable-environment shortcut.
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_initial_environment_precedes_runpath_but_not_rpath",
                "--nocapture",
            ])
            .env("FRANKENLIBC_SEARCH_CHILD_ROOT", &root)
            .env("FRANKENLIBC_SEARCH_CHILD_VALUE", expected.to_string())
            .env("LD_LIBRARY_PATH", dir.join("environment"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "child failed: {}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
fn native_nodelete_keeps_the_searched_dependency_closure_alive() {
    let _guard = GUARD.lock().unwrap_or_else(|error| error.into_inner());
    let dir = directory();
    // NODELETE retains these SONAMEs for the rest of the test process. Keep
    // them distinct from fixtures that exercise fresh dependency searches.
    let leaf = compile(
        &dir.join("plugins"),
        "search_nodelete_leaf",
        "int search_nodelete_tick(void) { static int n; return ++n; }",
        &[],
        None,
    );
    let root = compile(
        &dir,
        "search_nodelete_root",
        "extern int search_nodelete_tick(void); int search_answer(void) { return search_nodelete_tick(); }",
        &[&leaf],
        Some(("$ORIGIN/plugins", false)),
    );
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
    let leaf = compile(
        &real,
        "search_value",
        "int search_value(void) { return 11; }",
        &[],
        None,
    );
    compile(
        &alias,
        "search_value",
        "int search_value(void) { return 22; }",
        &[],
        None,
    );
    let root = compile(
        &real,
        "search_root",
        "extern int search_value(void); int search_answer(void) { return search_value(); }",
        &[&leaf],
        Some(("$ORIGIN", false)),
    );
    let link = alias.join(root.file_name().unwrap());
    std::os::unix::fs::symlink(&root, &link).unwrap();
    check(&link, 22);
}

// Keep the new capability regressions in the native-loader CI target too.
#[path = "native_loader_hwcaps_test.rs"]
mod hwcaps_regressions;
