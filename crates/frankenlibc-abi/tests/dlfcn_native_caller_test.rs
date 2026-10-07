#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{dlclose, dlerror, dlopen, dlsym, native_dso_handle_for_tests};
use frankenlibc_core::elf::ElfLoader;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
type Sym = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
type Error = unsafe extern "C" fn() -> *const c_char;
type Probe = unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char, *mut c_int) -> *mut c_void;

const SOURCE: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
int caller_target(void) { return VALUE; }
int caller_marker_WHO(void) { return VALUE; }
__thread int caller_tls = VALUE;
int caller_old(void) { return VALUE + 1; }
int caller_new(void) { return VALUE + 2; }
__asm__(".symver caller_old,caller_version@CALLER_1");
__asm__(".symver caller_new,caller_version@@CALLER_2");
__asm__(".globl caller_zero\n.set caller_zero,0");
static int indirect(void) { return VALUE + 3; }
static void *choose_indirect(void) { return indirect; }
int caller_ifunc(void) __attribute__((ifunc("choose_indirect")));
static void *choose_null(void) { return 0; }
int caller_null(void) __attribute__((ifunc("choose_null")));
void *caller_query_WHO(void *h, const char *name, const char *version, int *error) {
    dlerror();
    void *address = version ? dlvsym(h, name, version) : dlsym(h, name);
    *error = dlerror() != 0;
    __asm__ __volatile__("" : "+r"(address));
    return address;
}
static int init_result;
#ifdef LOOKUP_INIT
__attribute__((constructor)) static void initialize(void) {
    int (*target)(void) = dlsym(RTLD_DEFAULT, "caller_marker_C");
    init_result = target ? target() : -1;
}
#endif
int caller_init_result(void) { return init_result; }
"#;

const VERSIONS: &str = "CALLER_1 {}; CALLER_2 {} CALLER_1;\n";

#[derive(Clone, Copy)]
struct Api { open: Open, sym: Sym, close: Close, error: Error, native: bool }
impl Api {
    fn new(native: bool) -> Self {
        unsafe {
            if native { Self { open: dlopen, sym: dlsym, close: dlclose, error: dlerror, native } }
            else { Self {
                open: dlsym_oracle::host_fn(c"dlopen", dlopen as *const ()),
                sym: dlsym_oracle::host_fn(c"dlsym", dlsym as *const ()),
                close: dlsym_oracle::host_fn(c"dlclose", dlclose as *const ()),
                error: dlsym_oracle::host_fn(c"dlerror", dlerror as *const ()), native,
            } }
        }
    }
    fn open(&self, path: &Path, flags: c_int) -> *mut c_void {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(name.as_ptr(), flags | libc::RTLD_NOW) };
        assert!(!handle.is_null(), "open {path:?}, error {:?}", unsafe { (self.error)() });
        if self.native { assert!(native_dso_handle_for_tests(handle), "host fallback: {path:?}"); }
        handle
    }
    fn close(&self, handle: *mut c_void) { assert_eq!(unsafe { (self.close)(handle) }, 0); }
    fn symbol(&self, handle: *mut c_void, name: &CStr) -> *mut c_void {
        let address = unsafe { (self.sym)(handle, name.as_ptr()) };
        assert!(!address.is_null(), "explicit symbol {name:?}");
        address
    }
    fn loaded(&self, path: &Path) -> bool {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
        if handle.is_null() { false } else { self.close(handle); true }
    }
    fn probe(&self, handle: *mut c_void, who: &str) -> Probe {
        let name = CString::new(format!("caller_query_{who}")).unwrap();
        unsafe { std::mem::transmute(self.symbol(handle, &name)) }
    }
}

fn lookup(probe: Probe, scope: *mut c_void, name: &str, version: Option<&str>) -> (usize, bool) {
    let name = CString::new(name).unwrap();
    let version = version.map(|v| CString::new(v).unwrap());
    let mut error = -1;
    let address = unsafe {
        probe(scope, name.as_ptr(), version.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()), &mut error)
    };
    assert!(matches!(error, 0 | 1));
    (address as usize, error != 0)
}

fn target(probe: Probe, scope: *mut c_void, name: &str, version: Option<&str>) -> i32 {
    let (address, error) = lookup(probe, scope, name, version);
    assert!(!error && address != 0, "lookup {name} {version:?}: {address:#x} error={error}");
    let call: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(address) };
    unsafe { call() }
}

struct Fixture { dir: PathBuf }
impl Fixture {
    fn new(symbolic: bool, constructor: bool) -> Self {
        let dir = std::env::temp_dir().join(format!("frankenlibc-caller-{}-{}",
            std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("versions.map"), VERSIONS).unwrap();
        let fixture = Self { dir };
        for (who, value, deps) in [
            ("C", 40, &[][..]), ("S", 30, &[][..]), ("M", 20, &["C"][..]),
            ("R", 10, &["M", "S"][..]), ("G", 100, &[][..]), ("H", 200, &[][..]),
        ] { fixture.build(who, value, deps, symbolic && who == "R", constructor && who == "R"); }
        fixture
    }
    fn path(&self, who: &str) -> PathBuf { self.dir.join(format!("lib{who}.so")) }
    fn build(&self, who: &str, value: i32, deps: &[&str], symbolic: bool, constructor: bool) {
        let source = self.dir.join(format!("{who}.c"));
        std::fs::write(&source, SOURCE.replace("VALUE", &value.to_string()).replace("WHO", who)).unwrap();
        let mut command = Command::new("gcc");
        command.args(["-shared", "-fPIC", "-nostdlib", "-O2", "-fno-optimize-sibling-calls", "-Wl,--hash-style=both"])
            .arg(format!("-Wl,-soname,lib{who}.so"))
            .arg(format!("-Wl,--version-script={}", self.dir.join("versions.map").display()))
            .arg(&source).arg("-o").arg(self.path(who))
            .arg(format!("-L{}", self.dir.display())).arg("-Wl,--no-as-needed").arg("-Wl,-rpath,$ORIGIN");
        for dep in deps { command.arg(format!("-l{dep}")); }
        if symbolic { command.arg("-Wl,-Bsymbolic"); }
        if constructor { command.arg("-DLOOKUP_INIT"); }
        let output = command.output().expect("gcc is required");
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let bytes = std::fs::read(self.path(who)).unwrap();
        let object = ElfLoader::new(0).parse(&bytes).unwrap();
        assert_eq!(object.needed_libraries, deps.iter().map(|d| format!("lib{d}.so")).collect::<Vec<_>>());
        // Bare plugins must import the entry points the native binder intercepts.
        for name in ["dlsym", "dlvsym", "dlerror"] {
            assert!(object.undefined_symbols().any(|(_, sym)| object.symbol_name(sym) == Some(name)));
        }
    }
}

fn isolated(name: &str, scenario: fn(Api)) {
    if let Ok(mode) = std::env::var("FRANKENLIBC_CALLER_CHILD") {
        assert!(mode == "host" || mode == "native");
        scenario(Api::new(mode == "native"));
        return;
    }
    for mode in ["host", "native"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FRANKENLIBC_CALLER_CHILD", mode).spawn().unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{name}: {mode} failed: {status}");
                break;
            }
            if start.elapsed() > Duration::from_secs(30) {
                child.kill().unwrap(); child.wait().unwrap();
                panic!("{name}: {mode} timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn default_searches_callers_local_group_without_publishing_it() {
    isolated("default_searches_callers_local_group_without_publishing_it", |api| {
        let f = Fixture::new(false, false);
        let r = api.open(&f.path("R"), 0);
        let h = api.open(&f.path("H"), 0);
        for who in ["R", "M", "S", "C"] {
            let probe = api.probe(r, who);
            assert_eq!(target(probe, std::ptr::null_mut(), "caller_target", None), 10);
            for (name, value) in [("R", 10), ("M", 20), ("S", 30), ("C", 40)] {
                assert_eq!(target(probe, std::ptr::null_mut(), &format!("caller_marker_{name}"), None), value);
            }
            assert_eq!(lookup(probe, std::ptr::null_mut(), "caller_marker_H", None), (0, true));
        }
        assert_eq!(lookup(api.probe(h, "H"), std::ptr::null_mut(), "caller_marker_R", None), (0, true));
        api.close(h); api.close(r);
    });
}

#[test]
fn default_observes_global_promotion_order() {
    isolated("default_observes_global_promotion_order", |api| {
        let f = Fixture::new(false, false);
        let g = api.open(&f.path("G"), libc::RTLD_GLOBAL);
        let r = api.open(&f.path("R"), 0);
        let h = api.open(&f.path("H"), libc::RTLD_GLOBAL);
        for who in ["R", "M", "S", "C"] {
            let probe = api.probe(r, who);
            assert_eq!(target(probe, std::ptr::null_mut(), "caller_target", None), 100);
            assert_eq!(target(probe, std::ptr::null_mut(), "caller_marker_H", None), 200);
        }
        api.close(h); api.close(g); api.close(r);
        assert!(!api.loaded(&f.path("G"))); assert!(!api.loaded(&f.path("H")));
    });
}

#[test]
fn default_deepbind_precedes_globals_for_the_whole_new_group() {
    isolated("default_deepbind_precedes_globals_for_the_whole_new_group", |api| {
        let f = Fixture::new(false, false);
        let g = api.open(&f.path("G"), libc::RTLD_GLOBAL);
        let r = api.open(&f.path("R"), libc::RTLD_DEEPBIND);
        for who in ["R", "M", "S", "C"] {
            assert_eq!(target(api.probe(r, who), std::ptr::null_mut(), "caller_target", None), 10);
        }
        api.close(g); assert!(!api.loaded(&f.path("G"))); api.close(r);
    });
}

#[test]
fn default_symbolic_preference_is_own_object_not_whole_group() {
    isolated("default_symbolic_preference_is_own_object_not_whole_group", |api| {
        let f = Fixture::new(true, false);
        let g = api.open(&f.path("G"), libc::RTLD_GLOBAL);
        let r = api.open(&f.path("R"), 0);
        assert_eq!(target(api.probe(r, "R"), std::ptr::null_mut(), "caller_target", None), 10);
        assert_eq!(target(api.probe(r, "M"), std::ptr::null_mut(), "caller_target", None), 100);
        api.close(g); api.close(r);
    });
}

#[test]
fn default_membership_alone_does_not_pin_retired_roots() {
    isolated("default_membership_alone_does_not_pin_retired_roots", |api| {
        let f = Fixture::new(false, false);
        let g = api.open(&f.path("G"), libc::RTLD_GLOBAL);
        let r = api.open(&f.path("R"), libc::RTLD_DEEPBIND);
        let m = api.open(&f.path("M"), libc::RTLD_DEEPBIND);
        // No DEFAULT lookup before close: that would deliberately retain R.
        let probe = api.probe(m, "M"); api.close(r);
        assert!(!api.loaded(&f.path("R"))); assert!(!api.loaded(&f.path("S")));
        assert_eq!(lookup(probe, std::ptr::null_mut(), "caller_marker_R", None), (0, true));
        assert_eq!(target(probe, std::ptr::null_mut(), "caller_target", None), 100);
        assert_eq!(target(probe, std::ptr::null_mut(), "caller_marker_C", None), 40);
        api.close(g); api.close(m);
    });
}

#[test]
fn default_retains_successful_provider_but_not_misses() {
    isolated("default_retains_successful_provider_but_not_misses", |api| {
        let f = Fixture::new(false, false);
        let g = api.open(&f.path("G"), libc::RTLD_GLOBAL);
        let h = api.open(&f.path("H"), libc::RTLD_GLOBAL);
        let r = api.open(&f.path("R"), 0); let probe = api.probe(r, "R");
        assert_eq!(lookup(probe, std::ptr::null_mut(), "caller_missing", None), (0, true));
        let (address, error) = lookup(probe, std::ptr::null_mut(), "caller_marker_G", None);
        assert!(!error && address != 0);
        api.close(g); api.close(h);
        assert!(api.loaded(&f.path("G"))); assert!(!api.loaded(&f.path("H")));
        let call: unsafe extern "C" fn() -> i32 = unsafe { std::mem::transmute(address) };
        assert_eq!(unsafe { call() }, 100);
        api.close(r); assert!(!api.loaded(&f.path("G")));
    });
}

#[test]
fn default_versions_ifunc_and_zero_address_keep_error_distinctions() {
    isolated("default_versions_ifunc_and_zero_address_keep_error_distinctions", |api| {
        let f = Fixture::new(false, false); let r = api.open(&f.path("R"), 0);
        let probe = api.probe(r, "M");
        assert_eq!(target(probe, std::ptr::null_mut(), "caller_version", Some("CALLER_1")), 11);
        assert_eq!(target(probe, std::ptr::null_mut(), "caller_version", Some("CALLER_2")), 12);
        assert_eq!(lookup(probe, std::ptr::null_mut(), "caller_version", Some("MISSING")), (0, true));
        assert_eq!(target(probe, std::ptr::null_mut(), "caller_ifunc", None), 13);
        assert_eq!(lookup(probe, std::ptr::null_mut(), "caller_zero", None), (0, false));
        assert_eq!(lookup(probe, std::ptr::null_mut(), "caller_null", None), (0, false));
        api.close(r);
    });
}

#[test]
fn default_tls_uses_selected_module_and_calling_thread() {
    isolated("default_tls_uses_selected_module_and_calling_thread", |api| {
        let f = Fixture::new(false, false); let r = api.open(&f.path("R"), 0);
        let probe = api.probe(r, "M");
        let (address, error) = lookup(probe, std::ptr::null_mut(), "caller_tls", None);
        assert!(!error && address != 0);
        unsafe { assert_eq!(*(address as *const i32), 10); *(address as *mut i32) = 77; }
        assert_eq!(address, api.symbol(r, c"caller_tls") as usize);
        std::thread::spawn(move || {
            let (worker, error) = lookup(probe, std::ptr::null_mut(), "caller_tls", None);
            assert!(!error && worker != 0); assert_ne!(worker, address);
            unsafe { assert_eq!(*(worker as *const i32), 10); *(worker as *mut i32) = 88; }
        }).join().unwrap();
        unsafe { assert_eq!(*(address as *const i32), 77); }
        api.close(r);
    });
}

#[test]
fn default_lookup_is_available_during_native_initializers() {
    isolated("default_lookup_is_available_during_native_initializers", |api| {
        let f = Fixture::new(false, true); let r = api.open(&f.path("R"), 0);
        let call: unsafe extern "C" fn() -> i32 = unsafe { std::mem::transmute(api.symbol(r, c"caller_init_result")) };
        assert_eq!(unsafe { call() }, 40); api.close(r);
    });
}
