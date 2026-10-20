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
type Probe =
    unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char, *mut c_int) -> *mut c_void;

// Bare DSOs: importing lookup functions must use the native runtime bridge,
// not hide a native failure by naming the host runtime in DT_NEEDED. Every
// wrapper performs work after lookup, so the return PC belongs to that DSO.
const SOURCE: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
int next_target(void) { return VALUE; }
int next_marker_WHO(void) { return VALUE; }
__thread int next_tls = VALUE;
int next_old(void) { return VALUE + 1; }
int next_new(void) { return VALUE + 2; }
__asm__(".symver next_old,next_version@NEXT_1");
__asm__(".symver next_new,next_version@@NEXT_2");
__asm__(".globl next_zero\n.set next_zero,0");
__asm__(".pushsection .data\n.globl next_unique\n.type next_unique,@gnu_unique_object\n"
        ".size next_unique,4\nnext_unique:\n.long VALUE\n.popsection");
static int indirect(void) { return VALUE + 3; }
static void *choose_indirect(void) { return indirect; }
int next_ifunc(void) __attribute__((ifunc("choose_indirect")));
static void *choose_null(void) { return 0; }
int next_null(void) __attribute__((ifunc("choose_null")));
void *next_query_WHO(void *h, const char *name, const char *version, int *error) {
    dlerror();
    void *address = version ? dlvsym(h, name, version) : dlsym(h, name);
    *error = dlerror() != 0;
    __asm__ __volatile__("" : "+r"(address));
    return address;
}
int next_indirect_query_WHO(void) {
    void *(*lookup)(void *, const char *) = dlsym(RTLD_DEFAULT, "dlsym");
    if (!lookup) return -1;
    int (*target)(void) = lookup(RTLD_NEXT, "next_target");
    if (!target || dlerror()) return -2;
    return target();
}
static int init_result;
#ifdef NEXT_INIT
__attribute__((constructor)) static void initialize(void) {
    int (*target)(void) = dlsym(RTLD_NEXT, "next_target");
    init_result = target ? target() : -1;
}
#endif
int next_init_result_WHO(void) { return init_result; }
static int *trace;
void next_trace_WHO(int *value) { trace = value; }
__attribute__((destructor)) static void finalize(void) {
    if (!trace) return;
    dlerror();
    int (*target)(void) = dlsym(RTLD_NEXT, "next_target");
    *trace = target ? target() : dlerror() ? -2 : -3;
}
#ifdef NEXT_REENTRY
static int reentry_result;
static int reentry_impl(void) { return reentry_result; }
static void *choose_reentry(void) {
    dlerror();
    void *p = dlsym(RTLD_DEFAULT, "strlen");
    int a = p == 0 && dlerror() != 0;
    dlerror();
    p = dlsym(RTLD_NEXT, "strlen");
    int b = p == 0 && dlerror() != 0;
    reentry_result = a + 2 * b;
    return reentry_impl;
}
int next_reentry(void) __attribute__((ifunc("choose_reentry")));
int (*next_force_reentry)(void) = next_reentry;
int next_reentry_result(void) { return next_force_reentry(); }
#endif
"#;

const VERSIONS: &str = "NEXT_1 {}; NEXT_2 {} NEXT_1;\n";
const RECIPE: [(&str, i32, &[&str]); 11] = [
    ("C", 40, &[]),
    ("S", 30, &[]),
    ("M", 20, &["C"]),
    ("R", 10, &["M", "S"]),
    ("G", 100, &[]),
    ("H", 200, &[]),
    ("W", 300, &["M", "H"]),
    ("D", 80, &[]),
    ("E", 90, &[]),
    ("B", 70, &["D", "E"]),
    ("A", 60, &["B", "S"]),
];

#[derive(Clone, Copy)]
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
    fn open(&self, path: &Path, flags: c_int) -> *mut c_void {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(name.as_ptr(), flags | libc::RTLD_NOW) };
        assert!(!handle.is_null(), "open {path:?}, dlerror {:?}", unsafe {
            (self.error)()
        });
        if self.native {
            assert!(
                native_dso_handle_for_tests(handle),
                "host fallback: {path:?}"
            );
        }
        handle
    }
    fn close(&self, handle: *mut c_void) {
        assert_eq!(unsafe { (self.close)(handle) }, 0);
    }
    fn symbol(&self, handle: *mut c_void, name: &CStr) -> *mut c_void {
        let address = unsafe { (self.sym)(handle, name.as_ptr()) };
        assert!(!address.is_null(), "explicit symbol {name:?}");
        address
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
    fn probe(&self, handle: *mut c_void, who: &str) -> Probe {
        let name = CString::new(format!("next_query_{who}")).unwrap();
        unsafe { std::mem::transmute(self.symbol(handle, &name)) }
    }
}

fn lookup(probe: Probe, scope: *mut c_void, name: &str, version: Option<&str>) -> (usize, bool) {
    let name = CString::new(name).unwrap();
    let version = version.map(|v| CString::new(v).unwrap());
    let mut error = -1;
    let address = unsafe {
        probe(
            scope,
            name.as_ptr(),
            version.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
            &mut error,
        )
    };
    assert!(matches!(error, 0 | 1));
    (address as usize, error != 0)
}

fn target(probe: Probe, scope: *mut c_void, name: &str, version: Option<&str>) -> i32 {
    let (address, error) = lookup(probe, scope, name, version);
    assert!(
        !error && address != 0,
        "lookup {name} {version:?}: {address:#x} error={error}"
    );
    call(address)
}
fn call(address: usize) -> i32 {
    let function: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(address) };
    unsafe { function() }
}

struct Fixture {
    dir: PathBuf,
}
impl Fixture {
    fn new(symbolic: bool, constructor: bool, reentry: bool) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc-next-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("versions.map"), VERSIONS).unwrap();
        let fixture = Self { dir };
        for (who, value, deps) in RECIPE {
            let source = fixture.dir.join(format!("{who}.c"));
            std::fs::write(
                &source,
                SOURCE
                    .replace("VALUE", &value.to_string())
                    .replace("WHO", who),
            )
            .unwrap();
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
                .arg(format!("-Wl,-soname,lib{who}.so"))
                .arg(format!(
                    "-Wl,--version-script={}",
                    fixture.dir.join("versions.map").display()
                ))
                .arg(&source)
                .arg("-o")
                .arg(fixture.path(who))
                .arg(format!("-L{}", fixture.dir.display()))
                .arg("-Wl,--no-as-needed")
                .arg("-Wl,-rpath,$ORIGIN");
            for dep in deps {
                command.arg(format!("-l{dep}"));
            }
            if who == "R" {
                if symbolic {
                    command.arg("-Wl,-Bsymbolic");
                }
                if constructor {
                    command.arg("-DNEXT_INIT");
                }
                if reentry {
                    command.arg("-DNEXT_REENTRY");
                }
            }
            let output = command.output().expect("gcc is required");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let object = ElfLoader::new(0)
                .parse(&std::fs::read(fixture.path(who)).unwrap())
                .unwrap();
            assert_eq!(
                object.needed_libraries,
                deps.iter()
                    .map(|d| format!("lib{d}.so"))
                    .collect::<Vec<_>>()
            );
            for name in ["dlsym", "dlvsym", "dlerror"] {
                assert!(
                    object
                        .undefined_symbols()
                        .any(|(_, sym)| object.symbol_name(sym) == Some(name))
                );
            }
            let unique = object.lookup_symbol("next_unique").unwrap();
            assert_eq!(unique.st_info >> 4, 10, "fixture must emit STB_GNU_UNIQUE");
            if reentry && who == "R" {
                assert!(
                    object.rela_dyn.iter().any(|relocation| {
                        object
                            .dynsym
                            .get(relocation.symbol_index() as usize)
                            .is_some_and(|symbol| symbol.is_ifunc())
                    }),
                    "must resolve an IFUNC before registry publication"
                );
            }
        }
        fixture
    }
    fn path(&self, who: &str) -> PathBuf {
        self.dir.join(format!("lib{who}.so"))
    }
}

fn isolated(name: &str, native_only: bool, scenario: fn(Api)) {
    if let Ok(mode) = std::env::var("FRANKENLIBC_NEXT_CHILD") {
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
            .env("FRANKENLIBC_NEXT_CHILD", mode)
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
fn next_skips_the_caller_in_breadth_first_group_order() {
    isolated(
        "next_skips_the_caller_in_breadth_first_group_order",
        false,
        |api| {
            let f = Fixture::new(false, false, false);
            let r = api.open(&f.path("R"), 0);
            for (who, expected) in [("R", 20), ("M", 30), ("S", 40)] {
                let probe = api.probe(r, who);
                assert_eq!(
                    target(probe, libc::RTLD_NEXT, "next_target", None),
                    expected
                );
                assert_eq!(
                    lookup(probe, libc::RTLD_NEXT, &format!("next_marker_{who}"), None),
                    (0, true)
                );
            }
            assert_eq!(
                lookup(api.probe(r, "C"), libc::RTLD_NEXT, "next_target", None),
                (0, true)
            );
            api.close(r);
            for who in ["R", "M", "S", "C"] {
                assert!(!api.loaded(&f.path(who)));
            }
        },
    );
}

#[test]
fn next_excludes_unrelated_globals_and_host_builtins() {
    isolated(
        "next_excludes_unrelated_globals_and_host_builtins",
        false,
        |api| {
            let f = Fixture::new(false, false, false);
            let g = api.open(&f.path("G"), libc::RTLD_GLOBAL);
            let r = api.open(&f.path("R"), libc::RTLD_GLOBAL);
            let h = api.open(&f.path("H"), libc::RTLD_GLOBAL);
            let probe = api.probe(r, "R");
            assert_eq!(
                target(probe, std::ptr::null_mut(), "next_target", None),
                100
            );
            assert_eq!(target(probe, libc::RTLD_NEXT, "next_target", None), 20);
            for name in ["next_marker_G", "next_marker_H", "strlen", "dlsym"] {
                assert_eq!(
                    lookup(probe, libc::RTLD_NEXT, name, None),
                    (0, true),
                    "{name}"
                );
            }
            // Explicit handles remain explicit, even when lookup originates inside R.
            assert_eq!(target(probe, r, "next_target", None), 10);
            assert_eq!(target(probe, h, "next_target", None), 200);
            api.close(h);
            api.close(g);
            api.close(r);
        },
    );
}

#[test]
fn next_is_not_changed_by_deepbind_or_symbolic_self_preference() {
    isolated(
        "next_is_not_changed_by_deepbind_or_symbolic_self_preference",
        false,
        |api| {
            for symbolic in [false, true] {
                let f = Fixture::new(symbolic, false, false);
                let g = api.open(&f.path("G"), libc::RTLD_GLOBAL);
                let r = api.open(&f.path("R"), libc::RTLD_DEEPBIND);
                let probe = api.probe(r, "R");
                assert_eq!(target(probe, std::ptr::null_mut(), "next_target", None), 10);
                assert_eq!(target(probe, libc::RTLD_NEXT, "next_target", None), 20);
                api.close(g);
                api.close(r);
            }
        },
    );
}

#[test]
fn next_preserves_first_loader_across_dependency_reuse_and_reopen() {
    isolated(
        "next_preserves_first_loader_across_dependency_reuse_and_reopen",
        false,
        |api| {
            let f = Fixture::new(false, false, false);
            let m = api.open(&f.path("M"), 0);
            let r = api.open(&f.path("R"), 0);
            assert_eq!(
                target(api.probe(m, "M"), libc::RTLD_NEXT, "next_target", None),
                40
            );
            api.close(r);
            api.close(m);
            let r = api.open(&f.path("R"), 0);
            let m = api.open(&f.path("M"), libc::RTLD_DEEPBIND);
            assert_eq!(
                target(api.probe(m, "M"), libc::RTLD_NEXT, "next_target", None),
                30
            );
            api.close(r);
            assert_eq!(
                target(api.probe(m, "M"), libc::RTLD_NEXT, "next_target", None),
                40
            );
            api.close(m);
        },
    );
}

#[test]
fn next_does_not_reparent_to_a_newer_scope_after_original_root_retires() {
    isolated(
        "next_does_not_reparent_to_a_newer_scope_after_original_root_retires",
        false,
        |api| {
            let f = Fixture::new(false, false, false);
            let r = api.open(&f.path("R"), 0);
            let m = api.open(&f.path("M"), 0);
            let w = api.open(&f.path("W"), 0);
            let probe = api.probe(m, "M");
            api.close(r);
            assert!(!api.loaded(&f.path("R")));
            assert!(!api.loaded(&f.path("S")));
            assert_eq!(target(probe, libc::RTLD_NEXT, "next_target", None), 40);
            assert_eq!(
                lookup(probe, libc::RTLD_NEXT, "next_marker_H", None),
                (0, true)
            );
            assert_eq!(
                target(probe, std::ptr::null_mut(), "next_marker_H", None),
                200
            );
            api.close(w);
            api.close(m);
        },
    );
}

#[test]
fn next_does_not_retain_ordinary_ifunc_or_tls_providers() {
    isolated(
        "next_does_not_retain_ordinary_ifunc_or_tls_providers",
        false,
        |api| {
            let f = Fixture::new(false, false, false);
            let r = api.open(&f.path("R"), 0);
            let m = api.open(&f.path("M"), 0);
            let probe = api.probe(m, "M");
            assert_eq!(target(probe, libc::RTLD_NEXT, "next_marker_S", None), 30);
            assert_eq!(target(probe, libc::RTLD_NEXT, "next_ifunc", None), 33);
            let (tls, error) = lookup(probe, libc::RTLD_NEXT, "next_tls", None);
            assert!(!error && tls != 0);
            assert_eq!(unsafe { *(tls as *const c_int) }, 30);
            api.close(r);
            // Do not dereference any returned address after its provider unloads.
            assert!(!api.loaded(&f.path("R")));
            assert!(!api.loaded(&f.path("S")));
            assert_eq!(target(probe, libc::RTLD_NEXT, "next_target", None), 40);
            api.close(m);
        },
    );
}

#[test]
fn next_version_selection_and_successful_null_results() {
    isolated(
        "next_version_selection_and_successful_null_results",
        false,
        |api| {
            let f = Fixture::new(false, false, false);
            let r = api.open(&f.path("R"), 0);
            let probe = api.probe(r, "R");
            assert_eq!(
                target(probe, libc::RTLD_NEXT, "next_version", Some("NEXT_1")),
                21
            );
            assert_eq!(
                target(probe, libc::RTLD_NEXT, "next_version", Some("NEXT_2")),
                22
            );
            assert_eq!(target(probe, libc::RTLD_NEXT, "next_version", None), 22);
            assert_eq!(
                lookup(probe, libc::RTLD_NEXT, "next_version", Some("MISSING")),
                (0, true)
            );
            for name in ["next_zero", "next_null"] {
                assert_eq!(
                    lookup(probe, libc::RTLD_NEXT, name, None),
                    (0, false),
                    "{name}"
                );
            }
            assert_eq!(
                lookup(probe, libc::RTLD_NEXT, "next_absent", None),
                (0, true)
            );
            assert_eq!(target(probe, libc::RTLD_NEXT, "next_target", None), 20);
            api.close(r);
        },
    );
}

#[test]
fn next_tls_is_selected_by_scope_but_storage_is_per_thread() {
    isolated(
        "next_tls_is_selected_by_scope_but_storage_is_per_thread",
        false,
        |api| {
            let f = Fixture::new(false, false, false);
            let r = api.open(&f.path("R"), 0);
            let probe = api.probe(r, "R");
            let (parent, error) = lookup(probe, libc::RTLD_NEXT, "next_tls", None);
            assert!(!error && parent != 0);
            assert_eq!(unsafe { *(parent as *const c_int) }, 20);
            unsafe {
                *(parent as *mut c_int) = 77;
            }
            std::thread::spawn(move || {
                let (child, error) = lookup(probe, libc::RTLD_NEXT, "next_tls", None);
                assert!(!error && child != 0 && child != parent);
                assert_eq!(unsafe { *(child as *const c_int) }, 20);
                unsafe {
                    *(child as *mut c_int) = 88;
                }
                assert_eq!(
                    lookup(probe, libc::RTLD_NEXT, "next_tls", None),
                    (child, false)
                );
            })
            .join()
            .unwrap();
            assert_eq!(unsafe { *(parent as *const c_int) }, 77);
            api.close(r);
        },
    );
}

#[test]
fn next_unique_selection_still_uses_the_canonical_owner() {
    isolated(
        "next_unique_selection_still_uses_the_canonical_owner",
        false,
        |api| {
            let f = Fixture::new(false, false, false);
            let g = api.open(&f.path("G"), 0);
            let canonical = api.symbol(g, c"next_unique") as usize;
            assert_eq!(unsafe { *(canonical as *const c_int) }, 100);
            let r = api.open(&f.path("R"), 0);
            assert_eq!(
                lookup(api.probe(r, "R"), libc::RTLD_NEXT, "next_unique", None),
                (canonical, false)
            );
            api.close(g);
            assert!(api.loaded(&f.path("G")));
            api.close(r);
            assert!(!api.loaded(&f.path("M")));
            assert!(api.loaded(&f.path("G")));
        },
    );
}

#[test]
fn next_works_through_a_dynamically_obtained_lookup_function() {
    isolated(
        "next_works_through_a_dynamically_obtained_lookup_function",
        false,
        |api| {
            let f = Fixture::new(false, false, false);
            let r = api.open(&f.path("R"), 0);
            assert_eq!(call(api.symbol(r, c"next_indirect_query_R") as usize), 20);
            api.close(r);
        },
    );
}

#[test]
fn next_is_available_during_construction_and_batch_finalization() {
    isolated(
        "next_is_available_during_construction_and_batch_finalization",
        false,
        |api| {
            let f = Fixture::new(false, true, false);
            let r = api.open(&f.path("R"), 0);
            assert_eq!(call(api.symbol(r, c"next_init_result_R") as usize), 20);
            let mut trace = [-1; 4];
            for (index, who) in ["R", "M", "S", "C"].into_iter().enumerate() {
                let name = CString::new(format!("next_trace_{who}")).unwrap();
                let set: unsafe extern "C" fn(*mut c_int) =
                    unsafe { std::mem::transmute(api.symbol(r, &name)) };
                unsafe {
                    set(&mut trace[index]);
                }
            }
            api.close(r);
            assert_eq!(trace, [20, 30, 40, -2]);
        },
    );
}

#[test]
fn native_pending_ifunc_lookup_cannot_escape_to_the_host_namespace() {
    isolated(
        "native_pending_ifunc_lookup_cannot_escape_to_the_host_namespace",
        true,
        |api| {
            let f = Fixture::new(false, false, true);
            let r = api.open(&f.path("R"), 0);
            assert_eq!(call(api.symbol(r, c"next_reentry_result") as usize), 3);
            api.close(r);
        },
    );
}

#[test]
fn next_keeps_a_surviving_inner_ancestor_without_scope_membership() {
    isolated(
        "next_keeps_a_surviving_inner_ancestor_without_scope_membership",
        false,
        |api| {
            let f = Fixture::new(false, false, false);
            let a = api.open(&f.path("A"), libc::RTLD_GLOBAL);
            let g = api.open(&f.path("G"), 0);
            let probe = api.probe(a, "D");
            // This lifetime edge keeps B and its dependencies, but does not give
            // D a new load-scope membership. After A retires D's scope list is empty.
            assert_eq!(
                target(
                    api.probe(g, "G"),
                    std::ptr::null_mut(),
                    "next_marker_B",
                    None
                ),
                70
            );
            api.close(a);
            assert!(!api.loaded(&f.path("A")));
            assert!(api.loaded(&f.path("B")));
            // The surviving loader B searches [B,D,E], so NEXT from D finds E.
            // Remembering only the dead outer root A would incorrectly return miss.
            assert_eq!(target(probe, libc::RTLD_NEXT, "next_target", None), 90);
            api.close(g);
            assert!(!api.loaded(&f.path("B")));
            assert!(!api.loaded(&f.path("E")));
        },
    );
}
