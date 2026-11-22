#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(any(feature = "standalone", feature = "conformance-testing"))]
use std::sync::atomic::AtomicI32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{
    dlclose, dlerror, dlopen, dlsym, dlvsym, native_dso_handle_for_tests,
};
use frankenlibc_abi::glibc_internal_abi::{__tls_get_addr, TlsIndex, dlinfo};
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

static SERIAL: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
enum Loader {
    Native,
    Host,
}
impl Loader {
    fn open(self, path: &Path, flags: c_int) -> *mut c_void {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe {
            match self {
                Self::Native => dlopen(path.as_ptr(), flags),
                Self::Host => {
                    let open: unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void =
                        dlsym_oracle::host_fn(c"dlopen", dlopen as *const ());
                    open(path.as_ptr(), flags)
                }
            }
        };
        if matches!(self, Self::Native) && !handle.is_null() {
            assert!(
                native_dso_handle_for_tests(handle),
                "host fallback is not native TLS execution"
            );
        }
        handle
    }
    fn close(self, handle: *mut c_void) {
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
    fn lookup(self, handle: *mut c_void, name: &str, version: Option<&str>) -> *mut c_void {
        let name = CString::new(name).unwrap();
        unsafe {
            match version {
                None => match self {
                    Self::Native => dlsym(handle, name.as_ptr()),
                    Self::Host => {
                        let lookup: unsafe extern "C" fn(
                            *mut c_void,
                            *const c_char,
                        ) -> *mut c_void = dlsym_oracle::host_fn(c"dlsym", dlsym as *const ());
                        lookup(handle, name.as_ptr())
                    }
                },
                Some(version) => {
                    let version = CString::new(version).unwrap();
                    match self {
                        Self::Native => dlvsym(handle, name.as_ptr(), version.as_ptr()),
                        Self::Host => {
                            let lookup: unsafe extern "C" fn(
                                *mut c_void,
                                *const c_char,
                                *const c_char,
                            )
                                -> *mut c_void =
                                dlsym_oracle::host_fn(c"dlvsym", dlvsym as *const ());
                            lookup(handle, name.as_ptr(), version.as_ptr())
                        }
                    }
                }
            }
        }
    }
    fn symbol(self, handle: *mut c_void, name: &str) -> *mut c_void {
        let result = self.lookup(handle, name, None);
        assert!(!result.is_null(), "missing symbol {name}");
        result
    }
    fn value(self, handle: *mut c_void, name: &str) -> i64 {
        let function: unsafe extern "C" fn() -> i64 =
            unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { function() }
    }
    fn pointer(self, handle: *mut c_void, name: &str) -> *mut c_void {
        let function: unsafe extern "C" fn() -> *mut c_void =
            unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { function() }
    }
    fn tls_info(self, handle: *mut c_void) -> (usize, *mut c_void) {
        let mut module = 0usize;
        let mut base = std::ptr::null_mut();
        unsafe {
            assert_eq!(dlinfo(handle, 9, (&raw mut module).cast()), 0);
            assert_eq!(dlinfo(handle, 10, (&raw mut base).cast()), 0);
        }
        assert_ne!(module, 0);
        (module, base)
    }
}

struct Fixture {
    dir: PathBuf,
    prefix: String,
}
impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let prefix = format!("fl_tls_{}_{stamp}", std::process::id());
        let dir = std::env::temp_dir().join(&prefix);
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir, prefix }
    }
    fn name(&self, symbol: &str) -> String {
        symbol
            .replace("tls_value", &format!("{}_value", self.prefix))
            .replace("tls_event", &format!("{}_event", self.prefix))
    }
    fn compile(&self, name: &str, source: &str, dependencies: &[&Path], flags: &[&str]) -> PathBuf {
        let source_path = self.dir.join(format!("{name}.c"));
        let library = self.dir.join(format!("{name}.so"));
        std::fs::write(&source_path, self.name(source)).unwrap();
        let output = Command::new("cc")
            .args(["-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=none"])
            .arg(&source_path)
            .args(flags)
            .arg("-Wl,--no-as-needed")
            .args(dependencies)
            .arg("-o")
            .arg(&library)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cc failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        library
    }
    fn relocations(&self, path: &Path) -> String {
        let output = Command::new("readelf")
            .args(["-Wr"])
            .arg(path)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    }
}

fn child_case(name: &str) -> bool {
    if std::env::var("FL_TLS_CHILD").as_deref() == Ok(name) {
        return true;
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("FL_TLS_CHILD", name)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "TLS child {name} failed: {status}");
            return false;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("TLS operation deadlocked in {name}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn public_resolver_child(name: &str) -> bool {
    if std::env::var("FL_PUBLIC_TLS_CHILD").as_deref() == Ok(name) {
        return true;
    }
    for mode in ["strict", "hardened"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env("FL_PUBLIC_TLS_CHILD", name)
            .env("FRANKENLIBC_MODE", mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "public TLS child {name} ({mode}) timed out: {} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed;"),
            "public TLS child {name} ({mode}) did not execute successfully: {stdout} {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    false
}

const PUBLIC_TLS_SOURCE: &str = r#"
    struct payload { long prefix; long value; unsigned char zeroes[48]; };
    __thread struct payload tls_value __attribute__((aligned(64))) = {11, 41, {0}};
    long value(void) { return tls_value.value; }
    void *pointer(void) { return &tls_value.value; }
"#;

#[cfg(any(feature = "standalone", feature = "conformance-testing"))]
type TlsResolver = unsafe extern "C" fn(*const TlsIndex) -> *mut c_void;

#[cfg(feature = "standalone")]
const OWNED_TLS_RESOLVER: TlsResolver = __tls_get_addr;
#[cfg(all(not(feature = "standalone"), feature = "conformance-testing"))]
const OWNED_TLS_RESOLVER: TlsResolver =
    frankenlibc_abi::glibc_internal_abi::tls_get_addr_owned_for_conformance;

#[cfg(not(feature = "standalone"))]
#[test]
fn public_dynamic_tls_resolver_preserves_host_namespace() {
    if !public_resolver_child("public_dynamic_tls_resolver_preserves_host_namespace") {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fixture::new();
    let host_path = f.compile("public_host", PUBLIC_TLS_SOURCE, &[], &[]);
    let host = Loader::Host.open(&host_path, libc::RTLD_NOW);
    assert!(!host.is_null());
    let (host_module, host_base) = Loader::Host.tls_info(host);
    assert!(host_base.is_null());

    // Native IDs start at one in this isolated child. Keep the objects loaded
    // until a live native module has the SAME numeric ID as the host module.
    let native_path = f.compile(
        "public_native",
        &PUBLIC_TLS_SOURCE.replace("11, 41", "11, 777"),
        &[],
        &[],
    );
    let mut handles = Vec::new();
    let colliding_native = loop {
        let path = f.dir.join(format!("native_copy_{}.so", handles.len()));
        std::fs::copy(&native_path, &path).unwrap();
        let handle = Loader::Native.open(&path, libc::RTLD_NOW);
        assert!(!handle.is_null());
        handles.push(handle);
        let (native_module, _) = Loader::Native.tls_info(handle);
        assert!(
            native_module <= host_module,
            "missed host/native ID collision"
        );
        if native_module == host_module {
            break handle;
        }
    };
    let index = TlsIndex {
        ti_module: host_module as u64,
        ti_offset: 8,
    };
    assert!(unsafe { __tls_get_addr(std::ptr::null()) }.is_null());
    let resolved = unsafe { __tls_get_addr(&index) }.cast::<i64>();
    assert!(!resolved.is_null());
    assert_eq!(unsafe { *resolved }, 41);
    assert_eq!(resolved.cast(), Loader::Host.pointer(host, "pointer"));
    let native = Loader::Native
        .pointer(colliding_native, "pointer")
        .cast::<i64>();
    assert_eq!(unsafe { *native }, 777);
    assert_ne!(resolved, native);
    assert_eq!(unsafe { __tls_get_addr(&index) }, resolved.cast());
    for handle in handles {
        Loader::Native.close(handle);
    }
    assert_eq!(unsafe { *resolved }, 41);
    Loader::Host.close(host);
}

#[cfg(any(feature = "standalone", feature = "conformance-testing"))]
#[test]
fn public_dynamic_tls_resolver_uses_live_owned_registry() {
    if !public_resolver_child("public_dynamic_tls_resolver_uses_live_owned_registry") {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fixture::new();
    let path = f.compile("public_owned", PUBLIC_TLS_SOURCE, &[], &[]);
    assert!(f.relocations(&path).contains("DTPMOD64"));
    let handle = Loader::Native.open(&path, libc::RTLD_NOW);
    assert!(!handle.is_null());
    let (module, base) = Loader::Native.tls_info(handle);
    assert!(
        base.is_null(),
        "TLS must remain lazy until first valid access"
    );
    assert!(unsafe { OWNED_TLS_RESOLVER(std::ptr::null()) }.is_null());
    for (id, offset) in [
        (0, 0),
        (u64::MAX, 0),
        (module as u64, u64::MAX),
        (module as u64, 65),
    ] {
        let invalid = TlsIndex {
            ti_module: id,
            ti_offset: offset,
        };
        assert!(unsafe { OWNED_TLS_RESOLVER(&invalid) }.is_null());
    }
    assert!(Loader::Native.tls_info(handle).1.is_null());
    let index = TlsIndex {
        ti_module: module as u64,
        ti_offset: 8,
    };
    let resolved = unsafe { OWNED_TLS_RESOLVER(&index) }.cast::<i64>();
    assert!(!resolved.is_null());
    let base = Loader::Native.tls_info(handle).1.cast::<u8>();
    assert_eq!(base as usize % 64, 0);
    assert_eq!(resolved.cast::<u8>(), unsafe { base.add(8) });
    assert_eq!(resolved.cast(), Loader::Native.pointer(handle, "pointer"));
    assert_eq!(unsafe { *resolved }, 41);
    assert_eq!(unsafe { *base.cast::<i64>() }, 11);
    assert!(
        unsafe { std::slice::from_raw_parts(base.add(16), 48) }
            .iter()
            .all(|byte| *byte == 0)
    );
    let end = TlsIndex {
        ti_module: module as u64,
        ti_offset: 64,
    };
    assert_eq!(unsafe { OWNED_TLS_RESOLVER(&end) }.cast::<u8>(), unsafe {
        base.add(64)
    });
    unsafe { *resolved = 91 };
    let handle_address = handle as usize;
    let other_address = std::thread::spawn(move || {
        let handle = handle_address as *mut c_void;
        assert!(Loader::Native.tls_info(handle).1.is_null());
        let index = TlsIndex {
            ti_module: module as u64,
            ti_offset: 8,
        };
        let pointer = unsafe { OWNED_TLS_RESOLVER(&index) }.cast::<i64>();
        assert!(!pointer.is_null());
        assert_eq!(unsafe { *pointer }, 41);
        assert_eq!(pointer.cast(), Loader::Native.pointer(handle, "pointer"));
        unsafe { *pointer = 88 };
        assert_eq!(Loader::Native.value(handle, "value"), 88);
        pointer as usize
    })
    .join()
    .unwrap();
    assert_ne!(other_address, resolved as usize);
    assert_eq!(Loader::Native.value(handle, "value"), 91);
    assert_eq!(unsafe { OWNED_TLS_RESOLVER(&index) }, resolved.cast());
    Loader::Native.close(handle);
    assert!(
        unsafe { OWNED_TLS_RESOLVER(&index) }.is_null(),
        "retired ID stayed live"
    );
    let reloaded = Loader::Native.open(&path, libc::RTLD_NOW);
    assert!(!reloaded.is_null());
    let (new_module, base) = Loader::Native.tls_info(reloaded);
    assert_ne!(new_module, module, "TLS module IDs must never be reused");
    assert!(base.is_null());
    assert!(unsafe { OWNED_TLS_RESOLVER(&index) }.is_null());
    let fresh = TlsIndex {
        ti_module: new_module as u64,
        ti_offset: 8,
    };
    let fresh = unsafe { OWNED_TLS_RESOLVER(&fresh) }.cast::<i64>();
    assert!(!fresh.is_null());
    assert_eq!(unsafe { *fresh }, 41);
    Loader::Native.close(reloaded);
}

#[cfg(any(feature = "standalone", feature = "conformance-testing"))]
#[test]
fn public_dynamic_tls_resolver_isolates_native_threads() {
    if !public_resolver_child("public_dynamic_tls_resolver_isolates_native_threads") {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fixture::new();
    let source = format!(
        r#"{PUBLIC_TLS_SOURCE}
        #include <stddef.h>
        #include <stdint.h>
        #include <stdatomic.h>
        struct tls_index {{ size_t module; size_t offset; }};
        typedef void *(*resolve_fn)(const struct tls_index *);
        struct worker_case {{
            resolve_fn resolve; size_t module; long value;
            _Atomic int ready; _Atomic int release;
            uintptr_t address; long observed; int errors;
        }};
        void *worker(void *argument) {{
            struct worker_case *c = argument;
            struct tls_index index = {{c->module, offsetof(struct payload, value)}};
            long *p = c->resolve(&index);
            int errors = 0;
            if (!p) errors |= 1;
            else {{
                if (*p != 41) errors |= 2;
                if (p != &tls_value.value) errors |= 4;
                if (tls_value.prefix != 11 || ((uintptr_t)&tls_value % 64)) errors |= 8;
                for (size_t i=0; i<sizeof(tls_value.zeroes); ++i)
                    if (tls_value.zeroes[i]) errors |= 16;
                *p = c->value;
                c->address = (uintptr_t)p;
            }}
            atomic_store_explicit(&c->ready, 1, memory_order_release);
            while (!atomic_load_explicit(&c->release, memory_order_acquire))
                __asm__ volatile("pause");
            if (p) {{
                if (c->resolve(&index) != p) errors |= 32;
                c->observed = *p;
                if (*p != c->value) errors |= 64;
            }}
            c->errors = errors;
            return (void *)(uintptr_t)errors;
        }}
    "#
    );
    let path = f.compile("public_native_threads", &source, &[], &[]);
    let handle = Loader::Native.open(&path, libc::RTLD_NOW);
    assert!(!handle.is_null());
    let (module, _) = Loader::Native.tls_info(handle);
    type Worker = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
    let worker: Worker = unsafe { std::mem::transmute(Loader::Native.symbol(handle, "worker")) };
    let index = TlsIndex {
        ti_module: module as u64,
        ti_offset: 8,
    };
    let creator = unsafe { OWNED_TLS_RESOLVER(&index) }.cast::<i64>();
    assert!(!creator.is_null());
    unsafe { *creator = 303 };
    frankenlibc_abi::pthread_abi::pthread_threading_force_native_for_tests();

    #[repr(C)]
    struct WorkerCase {
        resolve: TlsResolver,
        module: usize,
        value: i64,
        ready: AtomicI32,
        release: AtomicI32,
        address: usize,
        observed: i64,
        errors: c_int,
    }
    // Repeated rounds also require new native workers to start from the TLS
    // template after the preceding workers' thread-exit cleanup has run.
    for _ in 0..2 {
        let mut cases = [101, 202].map(|value| WorkerCase {
            resolve: OWNED_TLS_RESOLVER,
            module,
            value,
            ready: AtomicI32::new(0),
            release: AtomicI32::new(0),
            address: 0,
            observed: 0,
            errors: 0,
        });
        let mut threads = [0; 2];
        for i in 0..2 {
            assert_eq!(
                unsafe {
                    frankenlibc_abi::pthread_abi::pthread_create(
                        &mut threads[i],
                        std::ptr::null(),
                        Some(worker),
                        (&raw mut cases[i]).cast(),
                    )
                },
                0
            );
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let ready = loop {
            if cases
                .iter()
                .all(|case| case.ready.load(Ordering::Acquire) == 1)
            {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        for case in &cases {
            case.release.store(1, Ordering::Release);
        }
        for thread in threads {
            let mut returned = std::ptr::null_mut();
            assert_eq!(
                unsafe { frankenlibc_abi::pthread_abi::pthread_join(thread, &mut returned) },
                0
            );
            assert!(
                returned.is_null(),
                "native TLS worker reported {returned:p}"
            );
        }
        assert!(ready, "native TLS workers did not both reach the barrier");
        assert_ne!(cases[0].address, cases[1].address);
        for case in &cases {
            assert_eq!(case.errors, 0);
            assert_eq!(case.observed, case.value);
            assert_ne!(case.address, creator as usize);
        }
        assert_eq!(unsafe { *creator }, 303);
        assert_eq!(unsafe { OWNED_TLS_RESOLVER(&index) }, creator.cast());
    }
    Loader::Native.close(handle);
}

#[test]
fn native_dynamic_tls_resolver_matches_imports_and_module_ownership() {
    if !child_case("native_dynamic_tls_resolver_matches_imports_and_module_ownership") {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let path = f.compile(
            "dynamic_resolver",
            r#"
            #define _GNU_SOURCE
            #include <dlfcn.h>
            #include <stddef.h>
            struct value_type { long prefix; long value; unsigned char zeroes[16]; };
            static __thread struct value_type tls_value = {11, 41, {0}};
            struct tls_index { size_t module; size_t offset; };
            extern void *__tls_get_addr(struct tls_index *);
            typedef void *(*resolve_fn)(struct tls_index *);
            long value(void) { return tls_value.value; }
            long probe(void *handle, int variant, long expected, int fresh) {
                const char *versions[] = {0, "GLIBC_2.3", "GLIBC_2.2.5",
                                         "GLIBC_PRIVATE", "GLIBC_9.99", ""};
                dlerror();
                void *address = variant
                    ? dlvsym(RTLD_DEFAULT, "__tls_get_addr", versions[variant])
                    : dlsym(RTLD_DEFAULT, "__tls_get_addr");
                if (variant >= 2) {
                    const char *error = dlerror();
                    return !address && error && *error ? 0 : -10;
                }
                /* Reject a wrong provider BEFORE it can interpret a native
                   module ID as an unrelated host DTV entry. */
                if (address != (void *)__tls_get_addr) return -11;
                if (dlerror()) return -12;
                size_t module = 0;
                void *base = 0;
                if (dlinfo(handle, RTLD_DI_TLS_MODID, &module) || !module) return -13;
                if (dlinfo(handle, RTLD_DI_TLS_DATA, &base)) return -14;
                if (fresh && base) return -15;
                struct tls_index index = {module, offsetof(struct value_type, value)};
                long *resolved = ((resolve_fn)address)(&index);
                if (!resolved || *resolved != expected) return -16;
                if (resolved != &tls_value.value) return -17;
                if (dlinfo(handle, RTLD_DI_TLS_DATA, &base) || !base) return -18;
                if ((char *)resolved - (char *)base != offsetof(struct value_type, value))
                    return -19;
                if (tls_value.prefix != 11 || tls_value.zeroes[15] != 0) return -20;
                return ++*resolved;
            }
        "#,
            &[],
            &[],
        );
        let handle = loader.open(&path, libc::RTLD_NOW);
        assert!(!handle.is_null());
        type Probe = unsafe extern "C" fn(*mut c_void, c_int, i64, c_int) -> i64;
        // SAFETY: the compiled fixture declares the exact probe signature.
        let probe: Probe = unsafe { std::mem::transmute(loader.symbol(handle, "probe")) };
        for version in 2..6 {
            assert_eq!(unsafe { probe(handle, version, 41, 1) }, 0);
        }
        assert_eq!(unsafe { probe(handle, 0, 41, 1) }, 42);
        assert_eq!(unsafe { probe(handle, 1, 42, 0) }, 43);
        let handle_address = handle as usize;
        std::thread::spawn(move || {
            let handle = handle_address as *mut c_void;
            assert_eq!(unsafe { probe(handle, 1, 41, 1) }, 42);
            assert_eq!(unsafe { probe(handle, 0, 42, 0) }, 43);
        })
        .join()
        .unwrap();
        assert_eq!(loader.value(handle, "value"), 43);
        loader.close(handle);
    }
}

#[test]
fn native_dynamic_tls_hooks_preserve_scoped_definitions() {
    if !child_case("native_dynamic_tls_hooks_preserve_scoped_definitions") {
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let version = f.dir.join("hooks.map");
        std::fs::write(
            &version,
            "FL_TLS_HOOK_1 { global: __tls_get_addr; __cxa_thread_atexit_impl; };",
        )
        .unwrap();
        let flag = format!("-Wl,--version-script={}", version.display());
        let path = f.compile(
            "scoped_hooks",
            r#"
            #define _GNU_SOURCE
            #include <dlfcn.h>
            void *__tls_get_addr(void *index) { return index; }
            int __cxa_thread_atexit_impl(void (*callback)(void *), void *arg, void *owner) {
                (void)callback; (void)arg; (void)owner;
                return 71;
            }
            long probe(void) {
                const char *names[] = {"__tls_get_addr", "__cxa_thread_atexit_impl"};
                void *expected[] = {(void *)__tls_get_addr, (void *)__cxa_thread_atexit_impl};
                for (unsigned i = 0; i < 2; ++i) {
                    if (dlsym(RTLD_DEFAULT, names[i]) != expected[i]) return 1;
                    /* A native definition may supply a version absent from the
                       builtin hook; its local scope must still be searched. */
                    if (dlvsym(RTLD_DEFAULT, names[i], "FL_TLS_HOOK_1") != expected[i]) return 2;
                }
                return 0;
            }
        "#,
            &[],
            &[&flag],
        );
        let handle = loader.open(&path, libc::RTLD_NOW | libc::RTLD_DEEPBIND);
        assert!(!handle.is_null());
        assert_eq!(loader.value(handle, "probe"), 0);
        loader.close(handle);
    }
}

#[test]
fn native_tls_data_bss_alignment_and_dlsym_match_host() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let path = f.compile(
            "data",
            r#"
            __thread long tls_value=7;
            __thread unsigned char zeroes[65536] __attribute__((aligned(4096)));
            long value(void){return tls_value;}
            void *address(void){return &tls_value;}
            void *aligned_address(void){return zeroes;}
            long zero_tail(void){return zeroes[65535];}
        "#,
            &[],
            &[],
        );
        let relocations = f.relocations(&path);
        assert!(relocations.contains("R_X86_64_DTPMOD64"));
        assert!(relocations.contains("R_X86_64_DTPOFF64"));
        let handle = loader.open(&path, libc::RTLD_NOW);
        assert!(
            !handle.is_null(),
            "TLS fixture was rejected by native loader"
        );
        assert_eq!(loader.value(handle, "value"), 7);
        assert_eq!(loader.value(handle, "zero_tail"), 0);
        assert_eq!(loader.pointer(handle, "aligned_address") as usize % 4096, 0);
        let variable = loader.symbol(handle, &f.name("tls_value"));
        assert_eq!(variable, loader.pointer(handle, "address"));
        unsafe {
            *variable.cast::<i64>() = 31;
        }
        assert_eq!(loader.value(handle, "value"), 31);
        loader.close(handle);
    }
}

#[test]
fn native_tls_existing_and_new_threads_are_isolated() {
    if !child_case("native_tls_existing_and_new_threads_are_isolated") {
        return;
    }
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let path = f.compile(
            "threads",
            r#"
            __thread long tls_value=5;
            __attribute__((constructor)) static void init(void){tls_value=77;}
            long value(void){return tls_value;} void *address(void){return &tls_value;}
        "#,
            &[],
            &[],
        );
        let barrier = Arc::new(Barrier::new(7));
        let shared = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for worker in 0..6 {
            let barrier = barrier.clone();
            let shared = shared.clone();
            let name = f.name("tls_value");
            workers.push(std::thread::spawn(move || {
                barrier.wait(); // These threads exist before the DSO is loaded.
                barrier.wait();
                let handle = shared.load(Ordering::Acquire) as *mut c_void;
                assert_eq!(loader.value(handle, "value"), 5);
                let variable = loader.symbol(handle, &name);
                assert_eq!(variable, loader.pointer(handle, "address"));
                unsafe {
                    *variable.cast::<i64>() = 100 + worker;
                }
                barrier.wait();
                assert_eq!(loader.value(handle, "value"), 100 + worker);
                variable as usize
            }));
        }
        barrier.wait();
        let handle = loader.open(&path, libc::RTLD_NOW);
        assert!(!handle.is_null());
        assert_eq!(loader.value(handle, "value"), 77);
        shared.store(handle as usize, Ordering::Release);
        barrier.wait();
        barrier.wait();
        let mut addresses = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        addresses.push(loader.pointer(handle, "address") as usize);
        addresses.sort_unstable();
        addresses.dedup();
        assert_eq!(addresses.len(), 7);
        assert_eq!(loader.value(handle, "value"), 77);
        let address = handle as usize;
        std::thread::spawn(move || {
            assert_eq!(loader.value(address as *mut c_void, "value"), 5);
        })
        .join()
        .unwrap();
        loader.close(handle);
    }
}

#[test]
fn native_tls_local_dynamic_executes() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let path=f.compile("local", "static __thread long value=19; static __thread long zero; long next(void){return ++value + zero++;}", &[], &["-O2","-ftls-model=local-dynamic"]);
        assert!(f.relocations(&path).contains("R_X86_64_DTPMOD64"));
        let handle = loader.open(&path, libc::RTLD_NOW);
        assert!(!handle.is_null());
        assert_eq!(loader.value(handle, "next"), 20);
        assert_eq!(loader.value(handle, "next"), 22);
        let address = handle as usize;
        std::thread::spawn(move || {
            assert_eq!(loader.value(address as *mut c_void, "next"), 20);
        })
        .join()
        .unwrap();
        loader.close(handle);
    }
}

#[test]
fn native_tls_template_uses_relocated_data() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let path = f.compile(
            "template",
            r#"
            long data[3]={40,41,42}; __thread long *pointer=&data[2];
            long read_value(void){return *pointer;} void *address(void){return pointer;}
        "#,
            &[],
            &[],
        );
        assert!(f.relocations(&path).contains("R_X86_64_64"));
        let handle = loader.open(&path, libc::RTLD_NOW);
        assert!(!handle.is_null());
        assert_eq!(loader.value(handle, "read_value"), 42);
        let data = loader.symbol(handle, "data");
        assert_eq!(
            loader.pointer(handle, "address") as usize,
            data as usize + 16
        );
        let address = handle as usize;
        std::thread::spawn(move || {
            assert_eq!(loader.value(address as *mut c_void, "read_value"), 42);
        })
        .join()
        .unwrap();
        loader.close(handle);
    }
}

#[test]
fn native_tls_relocation_only_provider_survives_close() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let provider = f.compile(
            "provider",
            "__thread long tls_value=10; long value(void){return tls_value;}",
            &[],
            &[],
        );
        let consumer = f.compile(
            "consumer",
            "extern __thread long tls_value; long next(void){return ++tls_value;}",
            &[],
            &[],
        );
        let first = loader.open(&provider, libc::RTLD_NOW | libc::RTLD_GLOBAL);
        assert!(!first.is_null());
        let second = loader.open(&consumer, libc::RTLD_NOW);
        assert!(!second.is_null());
        loader.close(first);
        assert_eq!(loader.value(second, "next"), 11);
        let address = second as usize;
        std::thread::spawn(move || {
            assert_eq!(loader.value(address as *mut c_void, "next"), 11);
        })
        .join()
        .unwrap();
        assert_eq!(loader.value(second, "next"), 12);
        let retained = loader.open(&provider, libc::RTLD_NOW | libc::RTLD_NOLOAD);
        assert_eq!(retained, first);
        assert_eq!(loader.value(retained, "value"), 12);
        loader.close(retained);
        loader.close(second);
        let gone = loader.open(&provider, libc::RTLD_NOW | libc::RTLD_NOLOAD);
        assert!(gone.is_null());
    }
}

#[test]
fn native_tls_dependency_versions_and_constructor_access() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let version = f.dir.join("tls.map");
        std::fs::write(&version, f.name("FL_TLS_1 { global: tls_value; }; ")).unwrap();
        let flag = format!("-Wl,--version-script={}", version.display());
        let provider = f.compile("provider", "__thread long tls_value=10;", &[], &[&flag]);
        let consumer = f.compile(
            "consumer",
            r#"
            extern __thread long tls_value;
            __attribute__((constructor)) static void init(void){tls_value+=7;}
            long value(void){return tls_value;} void *address(void){return &tls_value;}
        "#,
            &[&provider],
            &[],
        );
        let handle = loader.open(&consumer, libc::RTLD_NOW);
        assert!(!handle.is_null());
        assert_eq!(loader.value(handle, "value"), 17);
        let variable = loader.symbol(handle, &f.name("tls_value"));
        assert_eq!(variable, loader.pointer(handle, "address"));
        assert_eq!(
            variable,
            loader.lookup(handle, &f.name("tls_value"), Some("FL_TLS_1"))
        );
        assert!(
            loader
                .lookup(handle, &f.name("tls_value"), Some("FL_TLS_MISSING"))
                .is_null()
        );
        loader.close(handle);
    }
}

#[test]
fn native_tls_reopen_reload_and_nodelete_keep_correct_generations() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let path = f.compile(
            "generations",
            "__thread long tls_value=3; long next(void){return ++tls_value;}",
            &[],
            &[],
        );
        for _ in 0..16 {
            let first = loader.open(&path, libc::RTLD_NOW);
            assert!(!first.is_null());
            assert_eq!(loader.value(first, "next"), 4);
            let second = loader.open(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD);
            assert_eq!(first, second);
            loader.close(first);
            assert_eq!(loader.value(second, "next"), 5);
            loader.close(second);
        }
        let handle = loader.open(&path, libc::RTLD_NOW | libc::RTLD_NODELETE);
        assert!(!handle.is_null());
        assert_eq!(loader.value(handle, "next"), 4);
        loader.close(handle);
        let retained = loader.open(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD);
        assert_eq!(retained, handle);
        assert_eq!(loader.value(retained, "next"), 5);
        loader.close(retained);
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> usize {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn native_tls_malformed_metadata_and_relocations_rollback() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fixture::new();
    let sink = f.compile(
        "sink",
        "static long events; void tls_event(void){++events;} long count(void){return events;}",
        &[],
        &[],
    );
    let sink = Loader::Native.open(&sink, libc::RTLD_NOW | libc::RTLD_GLOBAL);
    assert!(!sink.is_null());
    let valid=f.compile("valid","extern void tls_event(void); __thread long tls_value=4; long value(void){return tls_value;} __attribute__((constructor)) static void init(void){tls_event();}",&[],&[]);
    let original = std::fs::read(&valid).unwrap();
    let phoff = u64_at(&original, 32) as usize;
    let phsize = u16_at(&original, 54);
    let tls = (0..u16_at(&original, 56))
        .map(|i| phoff + i * phsize)
        .find(|&i| u32_at(&original, i) == 7)
        .unwrap();
    let shoff = u64_at(&original, 40) as usize;
    let shsize = u16_at(&original, 58);
    let sections = (0..u16_at(&original, 60))
        .map(|i| shoff + i * shsize)
        .collect::<Vec<_>>();
    let rela = sections
        .iter()
        .filter(|&&i| u32_at(&original, i + 4) == 4)
        .find_map(|&i| {
            let start = u64_at(&original, i + 24) as usize;
            let size = u64_at(&original, i + 32) as usize;
            (start..start + size)
                .step_by(24)
                .find(|&i| matches!(u64_at(&original, i + 8) as u32, 16 | 17))
        })
        .unwrap();
    for case in 0..5 {
        let mut bytes = original.clone();
        match case {
            0 => put64(&mut bytes, tls + 40, 0),            // filesz > memsz
            1 => put64(&mut bytes, tls + 48, 3),            // invalid alignment
            2 => put64(&mut bytes, tls + 8, u64::MAX - 16), // template outside file
            3 => put64(&mut bytes, tls + 16, 0x1000_0000),  // template not backed by PT_LOAD
            4 => put64(&mut bytes, rela, u64::MAX - 7),     // invalid GOT target
            _ => unreachable!(),
        }
        let path = f.dir.join(format!("bad-{case}.so"));
        std::fs::write(&path, bytes).unwrap();
        assert!(
            Loader::Native.open(&path, libc::RTLD_NOW).is_null(),
            "malformed TLS case {case} loaded"
        );
        assert!(!unsafe { dlerror() }.is_null());
        assert_eq!(
            Loader::Native.value(sink, "count"),
            0,
            "initializer ran before validation"
        );
    }
    let handle = Loader::Native.open(&valid, libc::RTLD_NOW);
    assert!(!handle.is_null());
    assert_eq!(Loader::Native.value(handle, "value"), 4);
    assert_eq!(Loader::Native.value(sink, "count"), 1);
    Loader::Native.close(handle);
    Loader::Native.close(sink);
}

#[test]
#[allow(clippy::single_element_loop)]
fn native_tls_unsupported_models_are_not_silently_loaded() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fixture::new();
    // Initial-exec still requires integration with the host static TLS layout.
    // GNU2 descriptors now have execution and malformed-pair rollback coverage
    // in dlfcn_native_tlsdesc_test; blanket rejection is no longer the contract.
    for (index, flag, relocation) in [(0, "-ftls-model=initial-exec", "R_X86_64_TPOFF64")] {
        let path = f.compile(
            &format!("unsupported-{index}"),
            "__thread long tls_value=7; long value(void){return tls_value;}",
            &[],
            &[flag],
        );
        assert!(f.relocations(&path).contains(relocation));
        assert!(Loader::Native.open(&path, libc::RTLD_NOW).is_null());
        assert!(!unsafe { dlerror() }.is_null());
        let host = Loader::Host.open(&path, libc::RTLD_NOW);
        assert!(!host.is_null());
        assert_eq!(Loader::Host.value(host, "value"), 7);
        Loader::Host.close(host);
    }
}

#[test]
fn native_tls_unresolved_import_does_not_initialize_dependencies() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let sink = f.compile(
            "sink",
            "static long count; void tls_event(void){++count;} long events(void){return count;}",
            &[],
            &[],
        );
        let sink = loader.open(&sink, libc::RTLD_NOW | libc::RTLD_GLOBAL);
        assert!(!sink.is_null());
        let dependency=f.compile("dependency","extern void tls_event(void); __attribute__((constructor)) static void init(void){tls_event();}",&[],&[]);
        let root = f.compile(
            "missing",
            "extern __thread long tls_value; long value(void){return tls_value;}",
            &[&dependency],
            &[],
        );
        assert!(loader.open(&root, libc::RTLD_NOW).is_null());
        assert_eq!(loader.value(sink, "events"), 0);
        let handle = loader.open(&dependency, libc::RTLD_NOW);
        assert!(!handle.is_null());
        assert_eq!(loader.value(sink, "events"), 1);
        loader.close(handle);
        loader.close(sink);
    }
}
