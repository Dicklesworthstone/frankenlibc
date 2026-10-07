#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{
    dlclose, dlopen, dlsym, dlvsym, native_dso_handle_for_tests,
};
use frankenlibc_core::elf::ElfLoader;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

#[derive(Clone, Copy)]
enum Loader {
    Host,
    Native,
}

impl Loader {
    fn try_open(self, path: &Path, flags: c_int) -> *mut c_void {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: a live NUL-terminated pathname and the public loader ABI.
        let handle = unsafe {
            match self {
                Self::Native => dlopen(path.as_ptr(), flags),
                Self::Host => {
                    let open: unsafe extern "C" fn(*const libc::c_char, c_int) -> *mut c_void =
                        dlsym_oracle::host_fn(c"dlopen", dlopen as *const ());
                    open(path.as_ptr(), flags)
                }
            }
        };
        if !handle.is_null() && matches!(self, Self::Native) {
            assert!(native_dso_handle_for_tests(handle), "host fallback is not native unique binding");
        }
        handle
    }

    fn open(self, path: &Path, flags: c_int) -> *mut c_void {
        let handle = self.try_open(path, libc::RTLD_NOW | flags);
        assert!(!handle.is_null(), "unique fixture must load: {}", path.display());
        handle
    }

    fn close(self, handle: *mut c_void) {
        // SAFETY: each call releases exactly one successful open reference.
        let result = unsafe {
            match self {
                Self::Native => dlclose(handle),
                Self::Host => {
                    let close: unsafe extern "C" fn(*mut c_void) -> c_int =
                        dlsym_oracle::host_fn(c"dlclose", dlclose as *const ());
                    close(handle)
                }
            }
        };
        assert_eq!(result, 0);
    }

    fn symbol(self, handle: *mut c_void, name: &CStr) -> *mut c_void {
        // SAFETY: successful open reference and a NUL-terminated symbol name.
        let address = unsafe {
            match self {
                Self::Native => dlsym(handle, name.as_ptr()),
                Self::Host => {
                    let symbol: unsafe extern "C" fn(*mut c_void, *const libc::c_char) -> *mut c_void =
                        dlsym_oracle::host_fn(c"dlsym", dlsym as *const ());
                    symbol(handle, name.as_ptr())
                }
            }
        };
        assert!(!address.is_null(), "missing {name:?}");
        address
    }

    fn version(self, handle: *mut c_void, version: &CStr) -> *mut c_void {
        // SAFETY: same ABI, including two live NUL-terminated strings.
        let address = unsafe {
            match self {
                Self::Native => dlvsym(handle, c"fixture_unique".as_ptr(), version.as_ptr()),
                Self::Host => {
                    let symbol: unsafe extern "C" fn(*mut c_void, *const libc::c_char, *const libc::c_char) -> *mut c_void =
                        dlsym_oracle::host_fn(c"dlvsym", dlvsym as *const ());
                    symbol(handle, c"fixture_unique".as_ptr(), version.as_ptr())
                }
            }
        };
        assert!(!address.is_null(), "missing version {version:?}");
        address
    }

    fn getter(self, handle: *mut c_void, name: &CStr) -> *mut c_void {
        // SAFETY: the compiled fixture declares precisely int *getter(void).
        let call: unsafe extern "C" fn() -> *mut c_void =
            unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { call() }
    }

    fn resident(self, path: &Path) -> bool {
        let handle = self.try_open(path, libc::RTLD_NOW | libc::RTLD_NOLOAD);
        if handle.is_null() {
            false
        } else {
            self.close(handle);
            true
        }
    }
}

fn value(address: *mut c_void) -> c_int {
    // SAFETY: all call sites use live fixture int/TLS-int objects.
    unsafe { *address.cast::<c_int>() }
}

fn set_value(address: *mut c_void, value: c_int) {
    // SAFETY: tests do not concurrently access an ordinary int; TLS is local.
    unsafe { *address.cast::<c_int>() = value; }
}

/// Each test and each loader gets a new process. Unique owners deliberately
/// survive dlclose; sharing an oracle process would hide first-selection bugs.
/// Timeout is enforced outside the process which might deadlock in dlopen.
fn child_case(name: &str) -> Option<Loader> {
    child_case_with_loaders(name, &["host", "native"])
}

fn child_case_with_loaders(name: &str, loaders: &[&str]) -> Option<Loader> {
    if std::env::var("FL_UNIQUE_CHILD").as_deref() == Ok(name) {
        return Some(match std::env::var("FL_UNIQUE_LOADER").unwrap().as_str() {
            "host" => Loader::Host,
            "native" => Loader::Native,
            other => panic!("unknown loader {other}"),
        });
    }
    for &loader in loaders {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FL_UNIQUE_CHILD", name).env("FL_UNIQUE_LOADER", loader)
            .env_remove("LD_DYNAMIC_WEAK").spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{loader} unique child failed: {status}");
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("{loader} unique child deadlocked: {name}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    None
}

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fl_unique_{}_{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn compile(&self, name: &str, source: &str, flags: &[&str]) -> PathBuf {
        let input = self.dir.join(format!("{name}.cc"));
        let output = self.dir.join(format!("{name}.so"));
        std::fs::write(&input, source).unwrap();
        let result = Command::new("g++")
            .args(["-std=c++17", "-O2", "-shared", "-fPIC", "-nostdlib",
                   "-fno-exceptions", "-fno-rtti", "-Wl,--build-id=none"])
            .args(flags).arg(&input).arg("-o").arg(&output).output().unwrap();
        assert!(result.status.success(), "C++ fixture failed: {}", String::from_utf8_lossy(&result.stderr));
        let bytes = std::fs::read(&output).unwrap();
        let object = ElfLoader::new(0).parse(&bytes).unwrap();
        let has_unique = object.dynsym.iter().any(|symbol| symbol.st_info >> 4 == 10);
        assert_eq!(has_unique, source.contains("inline "), "fixture must exercise actual GNU unique binding");
        output
    }

    fn data(&self, name: &str, initial: i32, bare: bool) -> PathBuf {
        let getter = if bare { "" } else { "int *unique_address() { return &fixture_unique; }" };
        self.compile(name, &format!(
            "extern \"C\" {{ __attribute__((used)) inline int fixture_unique={initial}; {getter} }}"
        ), &[])
    }

    fn bad(&self, name: &str, initial: i32) -> PathBuf {
        let path = self.compile(name, &format!(r#"extern "C" {{
            inline int fixture_unique={initial};
            extern int undefined_fixture_symbol;
            int *unique_address() {{ return &fixture_unique; }}
            int *bad_address() {{ return &undefined_fixture_symbol; }}
        }}"#), &[]);
        // Force the valid unique relocation before the unresolved import.
        // Otherwise a negative test could pass without staging any selection.
        let mut bytes = std::fs::read(&path).unwrap();
        let object = ElfLoader::new(0).parse(&bytes).unwrap();
        let index = object.dynsym.iter().position(|s| object.symbol_name(s) == Some("fixture_unique")).unwrap();
        let u16_at = |b: &[u8], p| u16::from_le_bytes(b[p..p+2].try_into().unwrap()) as usize;
        let u64_at = |b: &[u8], p| u64::from_le_bytes(b[p..p+8].try_into().unwrap()) as usize;
        let start = u64_at(&bytes, 40);
        let stride = u16_at(&bytes, 58);
        let count = u16_at(&bytes, 60);
        for section in 0..count {
            let header = start + section * stride;
            let typ = u32::from_le_bytes(bytes[header+4..header+8].try_into().unwrap());
            if typ != 4 || u64_at(&bytes, header+8) & 2 == 0 { continue; }
            let offset = u64_at(&bytes, header+24);
            let size = u64_at(&bytes, header+32);
            assert_eq!(u64_at(&bytes, header+56), 24);
            let mut records = bytes[offset..offset+size].chunks_exact(24).map(<[u8]>::to_vec).collect::<Vec<_>>();
            records.sort_by_key(|r| (u64_at(r, 8) >> 32) != index);
            for (target, record) in bytes[offset..offset+size].chunks_exact_mut(24).zip(records) {
                target.copy_from_slice(&record);
            }
        }
        let reparsed = ElfLoader::new(0).parse(&bytes).unwrap();
        let names = reparsed.rela_dyn.iter().chain(&reparsed.rela_plt).filter_map(|r| {
            reparsed.dynsym.get(r.symbol_index() as usize).and_then(|s| reparsed.symbol_name(s))
        }).collect::<Vec<_>>();
        assert!(names.iter().position(|&s| s == "fixture_unique").unwrap()
            < names.iter().position(|&s| s == "undefined_fixture_symbol").unwrap());
        std::fs::write(&path, bytes).unwrap();
        path
    }
}

fn sharing(loader: Loader, flags: c_int) {
    let f = Fixture::new();
    let pa = f.data("owner", 17, false);
    let pb = f.data("duplicate", 41, false);
    let a = loader.open(&pa, 0);
    let b = loader.open(&pb, flags);
    let x = loader.symbol(a, c"fixture_unique");
    assert_eq!(x, loader.symbol(b, c"fixture_unique"), "LOCAL unique definitions must share identity");
    assert_eq!(x, loader.getter(a, c"unique_address"));
    assert_eq!(x, loader.getter(b, c"unique_address"));
    assert_eq!(value(x), 17);
    set_value(x, 99);
    loader.close(a);
    loader.close(b);
    assert!(loader.resident(&pa), "canonical provider must become NODELETE");
    assert!(!loader.resident(&pb), "non-owner duplicate must remain unloadable");
    let a = loader.open(&pa, 0);
    assert_eq!(value(loader.symbol(a, c"fixture_unique")), 99, "reopen must not reset unique state");
    loader.close(a);
}

#[test]
fn native_unique_local_identity_and_lifetime() {
    let Some(loader) = child_case("native_unique_local_identity_and_lifetime") else { return; };
    sharing(loader, 0);
}

#[test]
fn native_unique_deepbind_does_not_split_identity() {
    let Some(loader) = child_case("native_unique_deepbind_does_not_split_identity") else { return; };
    sharing(loader, libc::RTLD_DEEPBIND);
}

#[test]
fn native_unique_first_lookup_not_load_order_selects_owner() {
    let Some(loader) = child_case("native_unique_first_lookup_not_load_order_selects_owner") else { return; };
    let f = Fixture::new();
    let pa = f.data("first_loaded", 17, true);
    let pb = f.data("first_selected", 41, true);
    let a = loader.open(&pa, 0);
    let b = loader.open(&pb, 0);
    let x = loader.symbol(b, c"fixture_unique");
    assert_eq!(value(x), 41);
    assert_eq!(x, loader.symbol(a, c"fixture_unique"));
    loader.close(a); loader.close(b);
    assert!(!loader.resident(&pa));
    assert!(loader.resident(&pb));
}

#[test]
fn native_unique_unused_definition_does_not_pin() {
    let Some(loader) = child_case("native_unique_unused_definition_does_not_pin") else { return; };
    let f = Fixture::new();
    let path = f.data("unused", 17, true);
    let h = loader.open(&path, 0);
    loader.close(h);
    assert!(!loader.resident(&path));
}

#[test]
fn native_unique_ordinary_weak_definition_keeps_local_scope() {
    let Some(loader) = child_case("native_unique_ordinary_weak_definition_keeps_local_scope") else { return; };
    let f = Fixture::new();
    let pa = f.data("unique", 17, false);
    let pb = f.compile("weak", r#"extern "C" {
        __attribute__((weak)) int fixture_unique=41;
        int *unique_address() { return &fixture_unique; }
    }"#, &[]);
    let a = loader.open(&pa, 0);
    let b = loader.open(&pb, 0);
    assert_ne!(loader.symbol(a, c"fixture_unique"), loader.symbol(b, c"fixture_unique"));
    assert_eq!(value(loader.getter(b, c"unique_address")), 41);
    loader.close(b); loader.close(a);
    assert!(!loader.resident(&pb));
}

fn preemption(loader: Loader, explicit_lookup: bool) {
    let f = Fixture::new();
    let pa = f.compile("global", "extern \"C\" { int fixture_unique=17; }", &[]);
    let pb = f.data("unique", 41, false);
    let a = loader.open(&pa, libc::RTLD_GLOBAL);
    let b = loader.open(&pb, 0);
    assert_eq!(loader.getter(b, c"unique_address"), loader.symbol(a, c"fixture_unique"));
    if explicit_lookup {
        let own = loader.symbol(b, c"fixture_unique");
        assert_eq!(value(own), 41);
        assert_ne!(own, loader.symbol(a, c"fixture_unique"));
    }
    loader.close(b); loader.close(a);
    assert_eq!(loader.resident(&pb), explicit_lookup,
        "ordinary global preemption must not itself register a unique owner");
}

#[test]
fn native_unique_global_preemption_does_not_pin_unused_definition() {
    let Some(loader) = child_case("native_unique_global_preemption_does_not_pin_unused_definition") else { return; };
    preemption(loader, false);
}

#[test]
fn native_unique_handle_lookup_keeps_relocation_scope_distinct() {
    let Some(loader) = child_case("native_unique_handle_lookup_keeps_relocation_scope_distinct") else { return; };
    preemption(loader, true);
}

#[test]
fn native_unique_failed_load_rolls_back_new_owner() {
    let Some(loader) = child_case("native_unique_failed_load_rolls_back_new_owner") else { return; };
    let f = Fixture::new();
    let bad = f.bad("failed", 17);
    assert!(loader.try_open(&bad, libc::RTLD_NOW).is_null());
    assert!(!loader.resident(&bad));
    let good = f.data("successful", 41, false);
    let h = loader.open(&good, 0);
    assert_eq!(value(loader.getter(h, c"unique_address")), 41);
    loader.close(h);
}

#[test]
fn native_unique_failed_load_does_not_pin_resident_provider() {
    let Some(loader) = child_case("native_unique_failed_load_does_not_pin_resident_provider") else { return; };
    let f = Fixture::new();
    let pa = f.data("resident", 17, true);
    let bad = f.bad("failed", 41);
    let a = loader.open(&pa, libc::RTLD_GLOBAL);
    assert!(loader.try_open(&bad, libc::RTLD_NOW).is_null());
    loader.close(a);
    assert!(!loader.resident(&pa), "rollback must preserve the resident's unloadability");
}

fn tls_sharing(loader: Loader, descriptor: bool) {
    let f = Fixture::new();
    let flags: &[&str] = if descriptor { &["-mtls-dialect=gnu2"] } else { &["-mtls-dialect=gnu"] };
    let mut paths = Vec::new();
    for (name, initial) in [("owner", 17), ("duplicate", 41)] {
        paths.push(f.compile(name, &format!(r#"extern "C" {{
            inline thread_local int fixture_tls={initial};
            int *tls_address() {{ return &fixture_tls; }}
        }}"#), flags));
    }
    let a = loader.open(&paths[0], 0);
    let b = loader.open(&paths[1], 0);
    let x = loader.symbol(a, c"fixture_tls");
    assert_eq!(x, loader.symbol(b, c"fixture_tls"));
    assert_eq!(x, loader.getter(a, c"tls_address"));
    assert_eq!(x, loader.getter(b, c"tls_address"));
    assert_eq!(value(x), 17);
    set_value(x, 99);
    let (ha, hb) = (a as usize, b as usize);
    let child = std::thread::spawn(move || {
        let (a, b) = (ha as *mut c_void, hb as *mut c_void);
        let first = loader.symbol(a, c"fixture_tls");
        let second = loader.symbol(b, c"fixture_tls");
        assert_eq!(first, second);
        assert_eq!(value(first), 17, "TLS template belongs to the canonical provider");
        set_value(first, 77);
        assert_eq!(loader.getter(b, c"tls_address"), first);
        assert_eq!(value(second), 77);
        first as usize
    }).join().unwrap();
    assert_ne!(child, x as usize, "unique TLS means one object per thread, not per process");
    assert_eq!(value(x), 99);
    loader.close(a); loader.close(b);
    assert!(loader.resident(&paths[0]));
    assert!(!loader.resident(&paths[1]));
}

#[test]
fn native_unique_tls_general_dynamic_preserves_thread_isolation() {
    let Some(loader) = child_case("native_unique_tls_general_dynamic_preserves_thread_isolation") else { return; };
    tls_sharing(loader, false);
}

#[test]
fn native_unique_tlsdesc_preserves_thread_isolation() {
    let Some(loader) = child_case("native_unique_tlsdesc_preserves_thread_isolation") else { return; };
    tls_sharing(loader, true);
}

#[test]
fn native_unique_version_filter_precedes_name_canonicalization() {
    let Some(loader) = child_case("native_unique_version_filter_precedes_name_canonicalization") else { return; };
    let f = Fixture::new();
    let mut paths = Vec::new();
    for (version, initial) in [("FIRST", 17), ("SECOND", 41)] {
        let map = f.dir.join(format!("{version}.map"));
        std::fs::write(&map, format!("{version} {{ global: fixture_unique; local: *; }};\n")).unwrap();
        let flag = format!("-Wl,--version-script={}", map.display());
        paths.push(f.compile(version, &format!(
            "extern \"C\" {{ __attribute__((used)) inline int fixture_unique={initial}; }}"
        ), &[&flag]));
    }
    let a = loader.open(&paths[0], 0);
    let b = loader.open(&paths[1], 0);
    let x = loader.version(b, c"SECOND");
    assert_eq!(value(x), 41);
    assert_eq!(x, loader.version(a, c"FIRST"), "unique identity is by name after version matching");
    loader.close(a); loader.close(b);
    assert!(!loader.resident(&paths[0]));
    assert!(loader.resident(&paths[1]));
}

// This is a native lifecycle policy test, not a host-parity assertion: native
// worker cleanup deliberately refuses to resurrect its TLS state after the
// pthread reclaimer has destroyed it. A failed lookup must still be atomic.
// Exercise the real teardown path, without fault-injection hooks or OOM.
type KeySet = unsafe extern "C" fn(libc::pthread_key_t, *const c_void) -> c_int;

struct LateTlsLookup {
    key: libc::pthread_key_t,
    set: KeySet,
    warm_handle: usize,
    target_handle: usize,
    versioned: bool,
    rounds: std::sync::atomic::AtomicUsize,
    outcome: std::sync::atomic::AtomicUsize,
}

unsafe extern "C" fn lookup_after_tls_reclamation(pointer: *mut c_void) {
    use std::sync::atomic::Ordering;
    // SAFETY: the parent owns this boxed context until join has observed the
    // completion of every pthread destructor. Only atomic fields are written.
    let context = unsafe { &*pointer.cast::<LateTlsLookup>() };
    let round = context.rounds.fetch_add(1, Ordering::Relaxed);
    if round == 0 {
        // The native reclaimer runs in the first pthread destructor round.
        // Deferring to round two avoids depending on key allocation order.
        if unsafe { (context.set)(context.key, pointer) } != 0 {
            context.outcome.store(1, Ordering::Relaxed);
        }
        return;
    }
    if round != 1 {
        context.outcome.store(2, Ordering::Relaxed);
        return;
    }
    let warm = context.warm_handle as *mut c_void;
    // A non-TLS lookup must still work: a blanket rejection of dlsym during
    // teardown would otherwise make this regression pass for the wrong reason.
    if unsafe { dlsym(warm, c"fixture_marker".as_ptr()) }.is_null() {
        context.outcome.store(3, Ordering::Relaxed);
        return;
    }
    // Confirm that the earlier warmup's native TLS is no longer obtainable.
    // Failure here indicates a broken probe, NOT successful rollback coverage.
    if !unsafe { dlsym(warm, c"fixture_warm".as_ptr()) }.is_null() {
        context.outcome.store(4, Ordering::Relaxed);
        return;
    }
    let target = context.target_handle as *mut c_void;
    // SAFETY: the parent retains both handles throughout teardown, and all
    // names/version strings are constant, correctly terminated byte strings.
    let address = unsafe {
        if context.versioned {
            dlvsym(target, c"fixture_tls".as_ptr(), c"FIXTURE_TLS".as_ptr())
        } else {
            dlsym(target, c"fixture_tls".as_ptr())
        }
    };
    context.outcome.store(if address.is_null() { 100 } else { 5 }, Ordering::Relaxed);
}

fn failed_tls_lookup_is_atomic(loader: Loader, versioned: bool) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    assert!(matches!(loader, Loader::Native));
    let f = Fixture::new();
    let warm_path = f.compile("warm", r#"extern "C" {
        thread_local int fixture_warm = 7;
        int fixture_marker = 71;
    }"#, &[]);
    let map = f.dir.join("tls.map");
    std::fs::write(&map, "FIXTURE_TLS { global: fixture_tls; local: *; };\n").unwrap();
    let map_flag = format!("-Wl,--version-script={}", map.display());
    let map_flags = [map_flag.as_str()];
    let flags: &[&str] = if versioned { &map_flags } else { &[] };
    let paths: Vec<_> = [("rejected", 17), ("successful", 41)].into_iter().map(|(name, initial)| {
        f.compile(name, &format!(
            "extern \"C\" {{ __attribute__((used)) inline thread_local int fixture_tls={initial}; }}"
        ), flags)
    }).collect();
    // No relocation in these bare DSOs should select the unique name at load
    // time. Prove this from emitted metadata, not from the source spelling.
    for path in &paths {
        let bytes = std::fs::read(path).unwrap();
        let object = ElfLoader::new(0).parse(&bytes).unwrap();
        let index = object.dynsym.iter().position(|symbol| {
            object.symbol_name(symbol) == Some("fixture_tls") && symbol.is_tls()
                && symbol.st_info >> 4 == 10
        }).expect("fixture must export a GNU unique TLS definition");
        assert!(!object.rela_dyn.iter().chain(&object.rela_plt)
            .any(|relocation| relocation.symbol_index() as usize == index));
    }
    let warm = loader.open(&warm_path, 0);
    let rejected = loader.open(&paths[0], 0);
    let successful = loader.open(&paths[1], 0);

    type KeyCreate = unsafe extern "C" fn(
        *mut libc::pthread_key_t, Option<unsafe extern "C" fn(*mut c_void)>,
    ) -> c_int;
    type KeyDelete = unsafe extern "C" fn(libc::pthread_key_t) -> c_int;
    // Resolve host scheduling functions before entering teardown. None of
    // these keys contain native module IDs or replace the host's DTV.
    let (create, set, delete): (KeyCreate, KeySet, KeyDelete) = unsafe {
        (
            dlsym_oracle::host_fn(c"pthread_key_create",
                frankenlibc_abi::pthread_abi::pthread_key_create as *const ()),
            dlsym_oracle::host_fn(c"pthread_setspecific",
                frankenlibc_abi::pthread_abi::pthread_setspecific as *const ()),
            dlsym_oracle::host_fn(c"pthread_key_delete",
                frankenlibc_abi::pthread_abi::pthread_key_delete as *const ()),
        )
    };
    let mut key = 0;
    assert_eq!(unsafe { create(&mut key, Some(lookup_after_tls_reclamation)) }, 0);
    let context = Box::new(LateTlsLookup {
        key, set, warm_handle: warm as usize, target_handle: rejected as usize,
        versioned, rounds: AtomicUsize::new(0), outcome: AtomicUsize::new(0),
    });
    let pointer = (&*context as *const LateTlsLookup) as usize;
    let warm_handle = warm as usize;
    let worker = std::thread::spawn(move || {
        // Initialize real native thread state/Cleanup/reclaimer first.
        assert_eq!(value(loader.symbol(warm_handle as *mut c_void, c"fixture_warm")), 7);
        // The context remains owned by the parent through join below.
        assert_eq!(unsafe { set(key, pointer as *const c_void) }, 0);
    }).join();
    // Key deletion does not invoke callbacks; join has already completed them.
    assert_eq!(unsafe { delete(key) }, 0);
    worker.unwrap();
    assert_eq!(context.rounds.load(Ordering::Relaxed), 2, "both destructor rounds must run");
    assert_eq!(context.outcome.load(Ordering::Relaxed), 100,
        "must observe working ordinary lookup, reclaimed TLS, and a failed unique lookup");
    loader.close(rejected);
    assert!(!loader.resident(&paths[0]), "failed TLS lookup must not publish NODELETE");
    let chosen = if versioned {
        // This is fixture_tls, not the fixture_unique used by Loader::version.
        let pointer = unsafe { dlvsym(successful, c"fixture_tls".as_ptr(), c"FIXTURE_TLS".as_ptr()) };
        assert!(!pointer.is_null());
        pointer
    } else {
        loader.symbol(successful, c"fixture_tls")
    };
    assert_eq!(value(chosen), 41, "a failed lookup must not reserve the unique name");
    loader.close(successful);
    assert!(loader.resident(&paths[1]), "a successful first lookup must still pin its provider");
    loader.close(warm);
}

#[test]
fn native_unique_failed_tls_dlsym_does_not_pin_provider() {
    let Some(loader) = child_case_with_loaders(
        "native_unique_failed_tls_dlsym_does_not_pin_provider", &["native"],
    ) else { return; };
    failed_tls_lookup_is_atomic(loader, false);
}

#[test]
fn native_unique_failed_tls_dlvsym_does_not_publish_owner() {
    let Some(loader) = child_case_with_loaders(
        "native_unique_failed_tls_dlvsym_does_not_publish_owner", &["native"],
    ) else { return; };
    failed_tls_lookup_is_atomic(loader, true);
}
