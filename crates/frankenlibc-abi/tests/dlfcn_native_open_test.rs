#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{dlclose, dlerror, dlopen, dlsym, native_dso_handle_for_tests};
use frankenlibc_core::elf::ElfLoader;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
type Sym = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
type Error = unsafe extern "C" fn() -> *const c_char;
type Probe = unsafe extern "C" fn(*const c_char, c_int, *mut c_int) -> *mut c_void;

const ROOT: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
int open_private(void) { return 11; }
void *open_child(const char *name, int flags, int *error) {
    dlerror();
    void *handle = dlopen(name, flags);
    *error = dlerror() != 0;
    __asm__ __volatile__("" : "+r"(handle));
    return handle;
}
void *open_indirect(const char *name, int flags, int *error) {
    dlerror();
    void *(*open_fn)(const char *, int) = dlsym(RTLD_DEFAULT, "dlopen");
    void *handle = open_fn ? open_fn(name, flags) : 0;
    *error = dlerror() != 0;
    __asm__ __volatile__("" : "+r"(handle));
    return handle;
}
static void *constructor_handle;
#ifdef OPEN_CONSTRUCTOR
__attribute__((constructor)) static void initialize(void) {
    constructor_handle = dlopen("libchild.so", RTLD_NOW);
}
#endif
void *open_constructor_handle(void) { return constructor_handle; }
#ifdef OPEN_IFUNC
static int rejected;
static int implementation(void) { return rejected; }
static void *choose(void) {
    dlerror();
    void *handle = dlopen("libm.so.6", RTLD_NOW);
    rejected = handle == 0 && dlerror() != 0;
    return implementation;
}
int open_reentry(void) __attribute__((ifunc("choose")));
int (*open_force_reentry)(void) = open_reentry;
int open_reentry_result(void) { return open_force_reentry(); }
#endif
"#;

const CHILD: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
extern int dep_value(void);
__thread int child_tls = 17;
int child_value(void) { return 300 + dep_value(); }
void *child_open(const char *name, int flags, int *error) {
    dlerror();
    void *handle = dlopen(name, flags);
    *error = dlerror() != 0;
    __asm__ __volatile__("" : "+r"(handle));
    return handle;
}
"#;
const DEP: &str = "int dep_value(void) { return 17; }\n";
const GRAND: &str = "int grand_value(void) { return 88; }\n";
const RELATIVE: &str = "int relative_value(void) { return 99; }\n";
const IMPORTER: &str =
    "extern int open_private(void); int imported(void) { return open_private(); }\n";

#[derive(Clone, Copy)]
#[allow(dead_code)]
struct Api {
    open: Open,
    sym: Sym,
    close: Close,
    error: Error,
    native: bool,
}
impl Api {
    fn new(native: bool) -> Self {
        unsafe {
            if native {
                Self {
                    open: dlopen,
                    sym: dlsym,
                    close: dlclose,
                    error: dlerror,
                    native,
                }
            } else {
                Self {
                    open: dlsym_oracle::host_fn(c"dlopen", dlopen as *const ()),
                    sym: dlsym_oracle::host_fn(c"dlsym", dlsym as *const ()),
                    close: dlsym_oracle::host_fn(c"dlclose", dlclose as *const ()),
                    error: dlsym_oracle::host_fn(c"dlerror", dlerror as *const ()),
                    native,
                }
            }
        }
    }
    fn assert_native(&self, handle: *mut c_void) {
        assert!(!handle.is_null());
        if self.native {
            assert!(
                native_dso_handle_for_tests(handle),
                "unexpected host fallback"
            );
        }
    }
    fn open(&self, path: &Path) -> *mut c_void {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(name.as_ptr(), libc::RTLD_NOW) };
        self.assert_native(handle);
        handle
    }
    fn close(&self, handle: *mut c_void) {
        assert_eq!(unsafe { (self.close)(handle) }, 0);
    }
    fn symbol(&self, handle: *mut c_void, name: &CStr) -> *mut c_void {
        let address = unsafe { (self.sym)(handle, name.as_ptr()) };
        assert!(!address.is_null(), "symbol {name:?}");
        address
    }
    fn probe(&self, handle: *mut c_void, name: &CStr) -> Probe {
        unsafe { std::mem::transmute(self.symbol(handle, name)) }
    }
    fn value(&self, handle: *mut c_void, name: &CStr) -> c_int {
        let call: unsafe extern "C" fn() -> c_int =
            unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { call() }
    }
    fn loaded(&self, path: &Path) -> bool {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
        if handle.is_null() {
            false
        } else {
            self.close(handle);
            true
        }
    }
}

fn invoke(probe: Probe, name: Option<&str>, flags: c_int) -> (*mut c_void, bool) {
    let name = name.map(|s| CString::new(s).unwrap());
    let mut error = -1;
    let handle = unsafe {
        probe(
            name.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            &mut error,
        )
    };
    assert!(matches!(error, 0 | 1));
    (handle, error != 0)
}
fn open_child(api: Api, probe: Probe, name: &str, flags: c_int) -> *mut c_void {
    let (handle, error) = invoke(probe, Some(name), flags);
    assert!(!error, "caller dlopen({name}, {flags:#x}) failed");
    api.assert_native(handle);
    handle
}

struct Fixture {
    dir: PathBuf,
}
impl Fixture {
    fn new(rpath: bool, child_paths: bool, constructor: bool, ifunc: bool) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc-open-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for relative in ["plugins/children/grand", "cwd/relative"] {
            std::fs::create_dir_all(dir.join(relative)).unwrap();
        }
        let f = Self { dir };
        f.build("plugins/children/libdep.so", DEP, &[], None, false, &[]);
        f.build(
            "plugins/children/grand/libgrand.so",
            GRAND,
            &[],
            None,
            false,
            &[],
        );
        f.build(
            "cwd/relative/librelative.so",
            RELATIVE,
            &[],
            None,
            false,
            &[],
        );
        f.build(
            "plugins/children/libimporter.so",
            IMPORTER,
            &[],
            None,
            false,
            &[],
        );
        f.build(
            "plugins/children/libchild.so",
            CHILD,
            &["libdep.so"],
            child_paths.then_some("$ORIGIN:$ORIGIN/grand"),
            false,
            &[],
        );
        let mut defines = Vec::new();
        if constructor {
            defines.push("OPEN_CONSTRUCTOR");
        }
        if ifunc {
            defines.push("OPEN_IFUNC");
        }
        f.build(
            "plugins/libroot.so",
            ROOT,
            &[],
            Some("$ORIGIN/children"),
            rpath,
            &defines,
        );
        // A path containing a slash remains cwd-relative, unlike $ORIGIN.
        // This runs in its own subprocess, never in the parallel parent suite.
        std::env::set_current_dir(f.dir.join("cwd")).unwrap();
        f
    }
    fn root(&self) -> PathBuf {
        self.dir.join("plugins/libroot.so")
    }
    fn child(&self) -> PathBuf {
        self.dir.join("plugins/children/libchild.so")
    }
    fn build(
        &self,
        relative: &str,
        source: &str,
        deps: &[&str],
        search: Option<&str>,
        rpath: bool,
        defines: &[&str],
    ) {
        let output_path = self.dir.join(relative);
        let source_path = output_path.with_extension("c");
        std::fs::write(&source_path, source).unwrap();
        let soname = output_path.file_name().unwrap().to_str().unwrap();
        let mut command = Command::new("gcc");
        command
            .args([
                "-shared",
                "-fPIC",
                "-nostdlib",
                "-O2",
                "-fno-optimize-sibling-calls",
                "-Wl,--hash-style=both",
            ])
            .arg(format!("-Wl,-soname,{soname}"))
            .arg(&source_path)
            .arg("-o")
            .arg(&output_path)
            .arg(format!("-L{}", self.dir.join("plugins/children").display()))
            .arg(format!("-L{}", self.dir.join("plugins").display()))
            .arg("-Wl,--no-as-needed");
        for dep in deps {
            command.arg(format!("-l:{dep}"));
        }
        if let Some(search) = search {
            command.arg(if rpath {
                "-Wl,--disable-new-dtags"
            } else {
                "-Wl,--enable-new-dtags"
            });
            command.arg(format!("-Wl,-rpath,{search}"));
        }
        for define in defines {
            command.arg(format!("-D{define}"));
        }
        let output = command.output().expect("gcc is required");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let object = ElfLoader::new(0)
            .parse(&std::fs::read(&output_path).unwrap())
            .unwrap();
        assert_eq!(
            object.needed_libraries,
            deps.iter().map(|name| name.to_string()).collect::<Vec<_>>()
        );
        if source == ROOT || source == CHILD {
            assert!(
                object
                    .undefined_symbols()
                    .any(|(_, s)| object.symbol_name(s) == Some("dlopen"))
            );
        }
        if defines.contains(&"OPEN_IFUNC") {
            assert!(object.rela_dyn.iter().any(|r| {
                object
                    .dynsym
                    .get(r.symbol_index() as usize)
                    .is_some_and(|s| s.is_ifunc())
            }));
        }
    }
}

fn isolated(name: &str, native_only: bool, scenario: fn(Api)) {
    if let Ok(mode) = std::env::var("FRANKENLIBC_OPEN_CHILD") {
        assert!(mode == "host" || mode == "native");
        scenario(Api::new(mode == "native"));
        return;
    }
    for mode in if native_only {
        &["native"][..]
    } else {
        &["host", "native"][..]
    } {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FRANKENLIBC_OPEN_CHILD", mode)
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{name}: {mode} failed: {status}");
                break;
            }
            if start.elapsed() > Duration::from_secs(30) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{name}: {mode} timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn caller_runpath_origin_and_indirect_open_share_one_image() {
    isolated(
        "caller_runpath_origin_and_indirect_open_share_one_image",
        false,
        |api| {
            let f = Fixture::new(false, true, false, false);
            let root = api.open(&f.root());
            let probe = api.probe(root, c"open_child");
            assert_eq!(
                invoke(
                    probe,
                    Some("libchild.so"),
                    libc::RTLD_NOW | libc::RTLD_NOLOAD
                ),
                (std::ptr::null_mut(), false)
            );
            let child = open_child(api, probe, "libchild.so", libc::RTLD_NOW);
            assert_eq!(api.value(child, c"child_value"), 317);
            for name in [
                "$ORIGIN/children/libchild.so",
                "${ORIGIN}/children/libchild.so",
                "libchild.so",
            ] {
                let again = open_child(api, probe, name, libc::RTLD_NOW | libc::RTLD_NOLOAD);
                assert_eq!(again, child);
                api.close(again);
            }
            let indirect = open_child(
                api,
                api.probe(root, c"open_indirect"),
                "libchild.so",
                libc::RTLD_NOW,
            );
            assert_eq!(indirect, child);
            api.close(indirect);
            let (main, error) = invoke(probe, None, libc::RTLD_NOW);
            assert!(!error && !main.is_null());
            api.close(main);
            api.close(child);
            assert!(!api.loaded(&f.child()));
            api.close(root);
        },
    );
}

#[test]
fn caller_search_does_not_leak_into_a_new_groups_dependencies() {
    isolated(
        "caller_search_does_not_leak_into_a_new_groups_dependencies",
        false,
        |api| {
            for rpath in [false, true] {
                let f = Fixture::new(rpath, false, false, false);
                let root = api.open(&f.root());
                let probe = api.probe(root, c"open_child");
                let (child, error) = invoke(probe, Some("libchild.so"), libc::RTLD_NOW);
                // Both tags locate libchild, but neither is an implicit search
                // path for the independently dlopened child's libdep dependency.
                assert!(error && child.is_null());
                assert!(!api.loaded(&f.child()));
                // Give the child its own RUNPATH and retry the unchanged caller.
                f.build(
                    "plugins/children/libchild.so",
                    CHILD,
                    &["libdep.so"],
                    Some("$ORIGIN:$ORIGIN/grand"),
                    false,
                    &[],
                );
                let child = open_child(api, probe, "libchild.so", libc::RTLD_NOW);
                assert_eq!(api.value(child, c"child_value"), 317);
                api.close(child);
                api.close(root);
            }
        },
    );
}

#[test]
fn caller_path_with_slash_remains_cwd_relative() {
    isolated(
        "caller_path_with_slash_remains_cwd_relative",
        false,
        |api| {
            let f = Fixture::new(false, true, false, false);
            let root = api.open(&f.root());
            let probe = api.probe(root, c"open_child");
            let relative = open_child(api, probe, "relative/librelative.so", libc::RTLD_NOW);
            assert_eq!(api.value(relative, c"relative_value"), 99);
            assert!(
                invoke(probe, Some("children/libchild.so"), libc::RTLD_NOW)
                    .0
                    .is_null()
            );
            let child = open_child(api, probe, "$ORIGIN/children/libchild.so", libc::RTLD_NOW);
            assert_eq!(api.value(child, c"child_value"), 317);
            api.close(child);
            api.close(relative);
            api.close(root);
        },
    );
}

#[test]
fn caller_search_uses_loaded_metadata_after_backing_path_replacement() {
    isolated(
        "caller_search_uses_loaded_metadata_after_backing_path_replacement",
        false,
        |api| {
            let f = Fixture::new(false, true, false, false);
            let root = api.open(&f.root());
            let probe = api.probe(root, c"open_child");
            // Keep the old inode rather than changing bytes under a host mapping.
            std::fs::rename(f.root(), f.dir.join("plugins/retained-root.so")).unwrap();
            std::fs::write(f.root(), b"not an ELF object\n").unwrap();
            let child = open_child(api, probe, "libchild.so", libc::RTLD_NOW);
            assert_eq!(api.value(child, c"child_value"), 317);
            api.close(child);
            api.close(root);
        },
    );
}

#[test]
fn caller_constructor_and_nested_child_open_use_their_own_paths() {
    isolated(
        "caller_constructor_and_nested_child_open_use_their_own_paths",
        false,
        |api| {
            let f = Fixture::new(false, true, true, false);
            let root = api.open(&f.root());
            let constructor: unsafe extern "C" fn() -> *mut c_void =
                unsafe { std::mem::transmute(api.symbol(root, c"open_constructor_handle")) };
            let child = unsafe { constructor() };
            api.assert_native(child);
            assert_eq!(api.value(child, c"child_value"), 317);
            let nested = api.probe(child, c"child_open");
            api.close(root);
            let grand = open_child(api, nested, "libgrand.so", libc::RTLD_NOW);
            assert_eq!(api.value(grand, c"grand_value"), 88);
            api.close(grand);
            api.close(child);
            assert!(!api.loaded(&f.child()));
        },
    );
}

#[test]
fn caller_local_exports_do_not_become_child_relocation_scope() {
    isolated(
        "caller_local_exports_do_not_become_child_relocation_scope",
        false,
        |api| {
            let f = Fixture::new(false, true, false, false);
            let root = api.open(&f.root());
            let probe = api.probe(root, c"open_child");
            assert_eq!(api.value(root, c"open_private"), 11);
            for name in ["libimporter.so", "does-not-exist.so"] {
                let (handle, error) = invoke(probe, Some(name), libc::RTLD_NOW);
                assert!(error && handle.is_null(), "{name}");
            }
            let (handle, error) = invoke(probe, Some("libchild.so"), libc::RTLD_NOW | i32::MIN);
            assert!(error && handle.is_null());
            assert!(!api.loaded(&f.child()));
            let child = open_child(api, probe, "libchild.so", libc::RTLD_NOW);
            api.close(child);
            api.close(root);
        },
    );
}

#[test]
fn concurrent_caller_opens_publish_one_native_identity() {
    isolated(
        "concurrent_caller_opens_publish_one_native_identity",
        false,
        |api| {
            let f = Fixture::new(false, true, false, false);
            let root = api.open(&f.root());
            let probe = api.probe(root, c"open_child");
            let barrier = Arc::new(Barrier::new(8));
            let mut threads = Vec::new();
            for _ in 0..8 {
                let barrier = Arc::clone(&barrier);
                threads.push(std::thread::spawn(move || {
                    barrier.wait();
                    let child = open_child(api, probe, "libchild.so", libc::RTLD_NOW);
                    assert_eq!(api.value(child, c"child_value"), 317);
                    child as usize
                }));
            }
            let handles = threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .collect::<Vec<_>>();
            assert!(handles.iter().all(|h| *h == handles[0]));
            for handle in handles {
                api.close(handle as *mut c_void);
            }
            assert!(!api.loaded(&f.child()));
            api.close(root);
        },
    );
}

#[test]
fn caller_host_coupled_library_keeps_host_ownership() {
    isolated(
        "caller_host_coupled_library_keeps_host_ownership",
        false,
        |api| {
            let f = Fixture::new(false, true, false, false);
            let root = api.open(&f.root());
            let (handle, error) = invoke(
                api.probe(root, c"open_child"),
                Some("libm.so.6"),
                libc::RTLD_NOW,
            );
            assert!(!error && !handle.is_null());
            assert!(!native_dso_handle_for_tests(handle));
            let address = api.symbol(handle, c"cos");
            let host: unsafe extern "C" fn(f64) -> f64 = unsafe {
                dlsym_oracle::host_fn(c"cos", frankenlibc_abi::math_abi::cos as *const ())
            };
            assert_eq!(address as usize, host as *const () as usize);
            let call: unsafe extern "C" fn(f64) -> f64 = unsafe { std::mem::transmute(address) };
            assert_eq!(unsafe { call(0.0) }, 1.0);
            api.close(handle);
            api.close(root);
        },
    );
}

#[test]
fn native_caller_fifo_and_pending_ifunc_loads_are_rejected() {
    isolated(
        "native_caller_fifo_and_pending_ifunc_loads_are_rejected",
        true,
        |api| {
            let f = Fixture::new(false, true, false, true);
            let root = api.open(&f.root());
            assert_eq!(api.value(root, c"open_reentry_result"), 1);
            let fifo = f.dir.join("plugins/children/blocked.so");
            let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            let (handle, error) = invoke(
                api.probe(root, c"open_child"),
                Some("blocked.so"),
                libc::RTLD_NOW,
            );
            assert!(error && handle.is_null());
            let child = open_child(
                api,
                api.probe(root, c"open_child"),
                "libchild.so",
                libc::RTLD_NOW,
            );
            assert_eq!(api.value(child, c"child_value"), 317);
            api.close(child);
            api.close(root);
        },
    );
}

#[test]
fn caller_inherits_only_surviving_original_ancestors_rpath() {
    isolated(
        "caller_inherits_only_surviving_original_ancestors_rpath",
        false,
        |api| {
            let f = Fixture::new(false, true, false, false);
            f.build("plugins/libroot.so", ROOT, &[], None, false, &[]);
            f.build(
                "plugins/libouter.so",
                "int outer_value(void) { return 1; }\n",
                &["libroot.so"],
                Some("$ORIGIN:$ORIGIN/children"),
                true,
                &[],
            );
            let outer = api.open(&f.dir.join("plugins/libouter.so"));
            let root = api.open(&f.root());
            let probe = api.probe(root, c"open_child");
            let child = open_child(api, probe, "libchild.so", libc::RTLD_NOW);
            assert_eq!(api.value(child, c"child_value"), 317);
            api.close(child);
            assert!(!api.loaded(&f.child()));
            api.close(outer);
            assert!(!api.loaded(&f.dir.join("plugins/libouter.so")));
            let (child, error) = invoke(probe, Some("libchild.so"), libc::RTLD_NOW);
            assert!(
                error && child.is_null(),
                "retired ancestor RPATH must not survive"
            );
            let child = open_child(api, probe, "$ORIGIN/children/libchild.so", libc::RTLD_NOW);
            assert_eq!(api.value(child, c"child_value"), 317);
            api.close(child);
            api.close(root);
        },
    );
}
