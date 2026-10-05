//! Compile search/cache/CPU-policy tests despite ABI cfg(not(test)) gating.
//! Also execute real dependency-bearing DSOs, requiring a native-handle witness
//! and comparing the selected implementation with the host loader.
#[path = "../src/dlfcn_search.rs"]
mod search;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod execution {
    use std::ffi::{CString, c_int};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};
    use frankenlibc_abi::dlfcn_abi;

    static GUARD: Mutex<()> = Mutex::new(());
    const LEAF: &str = "libnative_hwcaps_value.so";
    const ROOT_CODE: &str = "extern int hwcaps_value(void); int hwcaps_answer(void) { return hwcaps_value(); }";

    fn directory() -> PathBuf {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("frankenlibc-hwcaps-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn compile(dir: &Path, filename: &str, code: &str, dependency: Option<&Path>, search: Option<(&str, bool)>, soname: Option<&Path>) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let source = dir.join(format!("{filename}.c"));
        let output = dir.join(filename);
        std::fs::write(&source, code).unwrap();
        let mut command = Command::new("cc");
        command.args(["-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=none", "-Wl,--no-as-needed"])
            .arg("-Xlinker").arg("-soname").arg("-Xlinker")
            .arg(soname.unwrap_or(Path::new(filename)))
            .arg("-o").arg(&output).arg(&source);
        if let Some((path, old_rpath)) = search {
            command.arg(if old_rpath { "-Wl,--disable-new-dtags" } else { "-Wl,--enable-new-dtags" })
                .arg("-Xlinker").arg("-rpath").arg("-Xlinker").arg(path);
        }
        if let Some(dependency) = dependency { command.arg(dependency); }
        let result = command.output().expect("C compiler required; never silently skip native execution");
        assert!(result.status.success(), "fixture compilation failed: {}", String::from_utf8_lossy(&result.stderr));
        output
    }

    fn leaf(dir: &Path, value: c_int) -> PathBuf {
        compile(dir, LEAF, &format!("int hwcaps_value(void) {{ return {value}; }}"), None, None, None)
    }

    fn variants(dir: &Path) -> PathBuf {
        let baseline = leaf(dir, 1);
        for level in 2..=4 {
            leaf(&dir.join(format!("glibc-hwcaps/x86-64-v{level}")), level);
        }
        baseline
    }

    fn host_answer(path: &Path) -> Option<c_int> {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid path to a generated, dependency-contained fixture.
        // libc calls the host ABI, not FrankenLibC's Rust-named test entrypoints.
        let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            let _ = unsafe { libc::dlerror() };
            return None;
        }
        let address = unsafe { libc::dlsym(handle, c"hwcaps_answer".as_ptr()) };
        assert!(!address.is_null(), "host fixture has no answer function");
        // SAFETY: every root exports exactly int hwcaps_answer(void).
        let answer: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(address) };
        let value = unsafe { answer() };
        assert_eq!(unsafe { libc::dlclose(handle) }, 0);
        Some(value)
    }

    fn check_native(path: &Path, expected: Option<c_int>) {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid generated fixture path, retained until after the call.
        let handle = unsafe { dlfcn_abi::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        let Some(expected) = expected else {
            assert!(handle.is_null(), "unsupported/missing variant unexpectedly loaded: {path:?}");
            return;
        };
        assert!(dlfcn_abi::native_dso_handle_for_tests(handle), "hwcaps fixture must load NATIVELY, not through host fallback: {path:?}");
        let address = unsafe { dlfcn_abi::dlsym(handle, c"hwcaps_answer".as_ptr()) };
        assert!(!address.is_null());
        // SAFETY: as above; dlclose follows execution, never precedes it.
        let answer: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(address) };
        let value = unsafe { answer() };
        let closed = unsafe { dlfcn_abi::dlclose(handle) };
        assert_eq!(value, expected);
        assert_eq!(closed, 0);
    }

    #[test]
    fn runpath_selects_the_same_capability_variant_as_the_host() {
        let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = directory();
        let baseline = variants(&dir.join("plugins"));
        let root = compile(&dir, "libhwcaps_root.so", ROOT_CODE, Some(&baseline), Some(("$ORIGIN/plugins", false)), None);
        let expected = host_answer(&root).expect("baseline makes the host fixture loadable");
        assert!((1..=4).contains(&expected));
        check_native(&root, Some(expected));
    }

    #[test]
    fn earlier_baseline_beats_later_variants_and_missing_variants_fall_back() {
        let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = directory();
        let first = leaf(&dir.join("first"), 11);
        variants(&dir.join("second"));
        let root = compile(&dir, "libhwcaps_root.so", ROOT_CODE, Some(&first), Some(("$ORIGIN/first:$ORIGIN/second", false)), None);
        assert_eq!(host_answer(&root), Some(11));
        check_native(&root, Some(11));
        let sparse = leaf(&dir.join("sparse"), 21);
        let root = compile(&dir, "libhwcaps_sparse.so", ROOT_CODE, Some(&sparse), Some(("$ORIGIN/absent:$ORIGIN/sparse", false)), None);
        assert_eq!(host_answer(&root), Some(21));
        check_native(&root, Some(21));
    }

    #[test]
    fn supported_hwcaps_only_dependency_does_not_need_a_baseline_file() {
        let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = directory();
        let only = leaf(&dir.join("plugins/glibc-hwcaps/x86-64-v2"), 2);
        let root = compile(&dir, "libhwcaps_root.so", ROOT_CODE, Some(&only), Some(("$ORIGIN/plugins", false)), None);
        let expected = host_answer(&root);
        assert!(expected.is_none() || expected == Some(2));
        check_native(&root, expected);
    }

    #[test]
    fn rpath_capability_search_is_inherited_by_transitive_dependencies() {
        let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = directory();
        let baseline = variants(&dir.join("plugins"));
        let middle = compile(&dir.join("plugins"), "libhwcaps_middle.so", "extern int hwcaps_value(void); int hwcaps_middle(void) { return hwcaps_value(); }", Some(&baseline), None, None);
        let root = compile(&dir, "libhwcaps_root.so", "extern int hwcaps_middle(void); int hwcaps_answer(void) { return hwcaps_middle(); }", Some(&middle), Some(("$ORIGIN/plugins", true)), None);
        let expected = host_answer(&root).expect("inherited RPATH reaches both dependencies");
        check_native(&root, Some(expected));
    }

    #[test]
    fn runpath_capability_search_does_not_leak_to_dependency_children() {
        let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = directory();
        let baseline = variants(&dir.join("plugins"));
        let middle = compile(&dir.join("plugins"), "libhwcaps_middle.so", "extern int hwcaps_value(void); int hwcaps_middle(void) { return hwcaps_value(); }", Some(&baseline), None, None);
        let root = compile(&dir, "libhwcaps_root.so", "extern int hwcaps_middle(void); int hwcaps_answer(void) { return hwcaps_middle(); }", Some(&middle), Some(("$ORIGIN/plugins", false)), None);
        assert_eq!(host_answer(&root), None);
        check_native(&root, None);
    }

    #[test]
    fn explicit_needed_path_bypasses_hwcaps_directory_search() {
        let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = directory();
        let exact = dir.join("exact").join(LEAF);
        let baseline = compile(&dir.join("exact"), LEAF, "int hwcaps_value(void) { return 31; }", None, None, Some(&exact));
        variants(&dir.join("plugins"));
        let root = compile(&dir, "libhwcaps_root.so", ROOT_CODE, Some(&baseline), Some(("$ORIGIN/plugins", false)), None);
        assert_eq!(host_answer(&root), Some(31));
        check_native(&root, Some(31));
    }
}
