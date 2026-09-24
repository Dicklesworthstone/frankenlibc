//! Executed native C++ termination, with live host comparisons where defined.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use frankenlibc_abi::dlfcn_abi::{dlclose, dlerror, dlopen, dlsym, native_dso_handle_for_tests};
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

#[derive(Clone, Copy)]
enum Loader { Host, Native }
impl Loader {
    fn open(self, path: &Path, flags: c_int) -> *mut c_void {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { match self {
            Self::Native => dlopen(path.as_ptr(), flags),
            Self::Host => {
                let f: unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void =
                    dlsym_oracle::host_fn(c"dlopen", dlopen as *const ());
                f(path.as_ptr(), flags)
            }
        }};
        if !handle.is_null() && matches!(self, Self::Native) {
            assert!(native_dso_handle_for_tests(handle), "host delegation is not native C++ execution");
        }
        handle
    }
    fn load(self, path: &Path, flags: c_int) -> *mut c_void {
        let handle = self.open(path, flags);
        assert!(!handle.is_null(), "C++ fixture failed to load: {path:?}");
        handle
    }
    fn symbol(self, handle: *mut c_void, name: &str) -> *mut c_void {
        let name = CString::new(name).unwrap();
        let result = unsafe { match self {
            Self::Native => dlsym(handle, name.as_ptr()),
            Self::Host => {
                let f: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void =
                    dlsym_oracle::host_fn(c"dlsym", dlsym as *const ());
                f(handle, name.as_ptr())
            }
        }};
        assert!(!result.is_null(), "missing fixture symbol {name:?}");
        result
    }
    fn value(self, handle: *mut c_void, name: &str) -> i64 {
        let f: unsafe extern "C" fn() -> i64 = unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { f() }
    }
    fn arg(self, handle: *mut c_void, name: &str, arg: usize) -> i64 {
        let f: unsafe extern "C" fn(usize) -> i64 = unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { f(arg) }
    }
    fn close(self, handle: *mut c_void) {
        let result = unsafe { match self {
            Self::Native => dlclose(handle),
            Self::Host => {
                let f: unsafe extern "C" fn(*mut c_void) -> c_int =
                    dlsym_oracle::host_fn(c"dlclose", dlclose as *const ());
                f(handle)
            }
        }};
        assert_eq!(result, 0);
    }
}

struct Fixture { dir: PathBuf, prefix: String }
impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let prefix = format!("fl_cxa_{}_{stamp}", std::process::id());
        let dir = std::env::temp_dir().join(&prefix);
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir, prefix }
    }
    fn source(&self, text: &str) -> String { text.replace("record_event", &format!("{}_event", self.prefix)) }
    fn compile(&self, name: &str, source: &str, cpp: bool, deps: &[&Path]) -> PathBuf {
        let path = self.dir.join(format!("{name}.{}", if cpp { "cc" } else { "c" }));
        let library = self.dir.join(format!("{name}.so"));
        std::fs::write(&path, self.source(source)).unwrap();
        let mut cmd = Command::new(if cpp { "c++" } else { "cc" });
        cmd.args(["-shared", "-fPIC", "-Wl,--build-id=none", "-Wl,--no-as-needed"]);
        if cpp {
            // Keep the real crtbeginS/crtendS: their __cxa_finalize FINI hook
            // and the compiler's __cxa_atexit calls are part of this test.
            cmd.args(["-nodefaultlibs", "-fno-exceptions", "-fno-rtti", "-fno-gnu-unique"]);
        } else { cmd.arg("-nostdlib"); }
        let output = cmd.arg(&path).args(deps).arg("-o").arg(&library).output().unwrap();
        assert!(output.status.success(), "C/C++ compilation failed: {}", String::from_utf8_lossy(&output.stderr));
        library
    }
    fn sink(&self) -> PathBuf {
        self.compile("sink", r#"
            static long trace, count, sum;
            void record_event(long n) { trace = (trace * 10 + n) % 1000000000; ++count; sum += n; }
            long events(void) { return trace; } long calls(void) { return count; }
            long total(void) { return sum; }
        "#, false, &[])
    }
}

fn child(name: &str) -> bool {
    if std::env::var("FL_CXA_CHILD").as_deref() == Ok(name) { return true; }
    let mut child = Command::new(std::env::current_exe().unwrap()).args(["--exact", name, "--nocapture"])
        .env("FL_CXA_CHILD", name).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "C++ child {name} failed: {status}"); return false;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap(); let _ = child.wait(); panic!("C++ finalization deadlocked: {name}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

const API: &str = r#"
    extern void record_event(long);
    extern int __cxa_atexit(void (*)(void *), void *, void *);
    extern void __cxa_finalize(void *);
    static char token;
    static void emit(void *p) { record_event((long)p); }
    long add(long n) { return __cxa_atexit(emit, (void *)n, &token); }
    long finish(void) { __cxa_finalize(&token); return 0; }
    __attribute__((destructor)) static void fini(void) { __cxa_finalize(&token); }
"#;

#[test]
fn native_cxa_real_cpp_static_objects_execute_and_reload() {
    if !child("native_cxa_real_cpp_static_objects_execute_and_reload") { return; }
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new(); let sink_path = f.sink(); let sink = loader.load(&sink_path, libc::RTLD_NOW);
        let path = f.compile("objects", r#"
            extern "C" void record_event(long);
            struct Object { long n; Object(long v): n(v) { record_event(v); }
                ~Object() { record_event(6-n); } };
            Object first(1), second(2);
            extern "C" long answer(void) { return first.n + second.n; }
        "#, true, &[&sink_path]);
        let symbols = Command::new("readelf").args(["-Ws"]).arg(&path).output().unwrap();
        let symbols = String::from_utf8(symbols.stdout).unwrap();
        assert!(symbols.contains("__cxa_atexit") && symbols.contains("__cxa_finalize"));
        for round in 0..3 {
            let handle = loader.load(&path, libc::RTLD_NOW);
            assert_eq!(loader.value(handle, "answer"), 3);
            assert_eq!(loader.value(sink, "calls"), round * 4 + 2);
            let again = loader.load(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD);
            assert_eq!(again, handle); loader.close(again);
            assert_eq!(loader.value(sink, "calls"), round * 4 + 2);
            loader.close(handle);
            assert_eq!(loader.value(sink, "calls"), round * 4 + 4);
            assert_eq!(loader.value(sink, "events") % 10000, 1245);
        }
        loader.close(sink);
    }
}

#[test]
fn native_cxa_scoped_finalize_is_exactly_once() {
    if !child("native_cxa_scoped_finalize_is_exactly_once") { return; }
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new(); let s = f.sink(); let sink = loader.load(&s, libc::RTLD_NOW);
        let a = f.compile("a", API, false, &[&s]); let b = f.compile("b", API, false, &[&s]);
        let a = loader.load(&a, libc::RTLD_NOW); let b = loader.load(&b, libc::RTLD_NOW);
        assert_eq!(loader.arg(a, "add", 1), 0); assert_eq!(loader.arg(b, "add", 2), 0);
        assert_eq!(loader.arg(a, "add", 3), 0);
        loader.value(a, "finish"); loader.value(a, "finish");
        assert_eq!(loader.value(sink, "events"), 31);
        loader.close(a); assert_eq!(loader.value(sink, "events"), 31);
        loader.close(b); assert_eq!(loader.value(sink, "events"), 312); loader.close(sink);
    }
}

#[test]
fn native_cxa_recursion_and_new_registrations_keep_lifo_order() {
    if !child("native_cxa_recursion_and_new_registrations_keep_lifo_order") { return; }
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new(); let s = f.sink(); let sink = loader.load(&s, libc::RTLD_NOW);
        let text = format!("{API}\n{}", r#"
            static void recursive(void *p) {
                record_event(4); __cxa_atexit(emit, (void *)5, &token);
                __cxa_finalize(&token); record_event(6);
            }
            long setup(void) { add(3); return __cxa_atexit(recursive, 0, &token); }
        "#);
        let p = f.compile("recursive", &text, false, &[&s]); let h = loader.load(&p, libc::RTLD_NOW);
        assert_eq!(loader.value(h, "setup"), 0); loader.close(h);
        assert_eq!(loader.value(sink, "events"), 4536); loader.close(sink);
    }
}

#[test]
fn native_cxa_matches_exact_tokens_not_just_owning_library() {
    if !child("native_cxa_matches_exact_tokens_not_just_owning_library") { return; }
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new(); let s = f.sink(); let sink = loader.load(&s, libc::RTLD_NOW);
        let text = format!("{API}\n{}", r#"
            static char other;
            long add_other(long n) { return __cxa_atexit(emit, (void *)n, &other); }
            long finish_other(void) { __cxa_finalize(&other); return 0; }
        "#);
        let p = f.compile("tokens", &text, false, &[&s]); let h = loader.load(&p, libc::RTLD_NOW);
        assert_eq!(loader.arg(h, "add", 1), 0); assert_eq!(loader.arg(h, "add_other", 2), 0);
        assert_eq!(loader.arg(h, "add", 3), 0); loader.value(h, "finish");
        assert_eq!(loader.value(sink, "events"), 31); loader.value(h, "finish_other");
        assert_eq!(loader.value(sink, "events"), 312); loader.close(h); loader.close(sink);
    }
}

#[test]
fn native_cxa_concurrent_finalize_consumes_each_entry_once() {
    if !child("native_cxa_concurrent_finalize_consumes_each_entry_once") { return; }
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let s = f.compile("sink", r#"
            static long count, sum;
            void record_event(long n) { __atomic_fetch_add(&count, 1, 0); __atomic_fetch_add(&sum,n,0); }
            long calls(void) { return count; } long total(void) { return sum; }
        "#, false, &[]);
        let sink = loader.load(&s, libc::RTLD_NOW); let p = f.compile("concurrent", API, false, &[&s]);
        let h = loader.load(&p, libc::RTLD_NOW);
        for n in 0..128 { assert_eq!(loader.arg(h, "add", n), 0); }
        let address = h as usize;
        let workers = (0..8).map(|_| std::thread::spawn(move || {
            loader.value(address as *mut c_void, "finish");
        })).collect::<Vec<_>>();
        for w in workers { w.join().unwrap(); }
        loader.close(h); assert_eq!(loader.value(sink, "calls"), 128);
        assert_eq!(loader.value(sink, "total"), 8128); loader.close(sink);
    }
}

#[test]
fn native_cxa_callback_provider_is_retained_without_needed_edge() {
    if !child("native_cxa_callback_provider_is_retained_without_needed_edge") { return; }
    let loader = Loader::Native; let f = Fixture::new(); let s = f.sink();
    let sink = loader.load(&s, libc::RTLD_NOW);
    let provider_path = f.compile("provider", "extern void record_event(long); void callback(void *p) { record_event(*(long *)p); }", false, &[&s]);
    let owner_path = f.compile("owner", r#"
        extern int __cxa_atexit(void (*)(void *), void *, void *);
        extern void __cxa_finalize(void *); static char token; static long value=7;
        long install(void (*f)(void *)) { return __cxa_atexit(f, &value, &token); }
        __attribute__((destructor)) static void fini(void) { __cxa_finalize(&token); }
    "#, false, &[]);
    let provider = loader.load(&provider_path, libc::RTLD_NOW); let owner = loader.load(&owner_path, libc::RTLD_NOW);
    assert_eq!(loader.arg(owner, "install", loader.symbol(provider, "callback") as usize), 0);
    loader.close(provider); assert!(native_dso_handle_for_tests(provider));
    loader.close(owner); assert_eq!(loader.value(sink, "events"), 7);
    assert!(!native_dso_handle_for_tests(provider)); loader.close(sink);
}

#[test]
fn native_cxa_nested_dlclose_defers_library_finalizers() {
    if !child("native_cxa_nested_dlclose_defers_library_finalizers") { return; }
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new(); let s = f.sink(); let sink = loader.load(&s, libc::RTLD_NOW);
        let victim = f.compile("victim", "extern void record_event(long); __attribute__((destructor)) static void fini(void) { record_event(4); }", false, &[&s]);
        let victim = loader.load(&victim, libc::RTLD_NOW);
        let text = format!("{API}\n{}", r#"
            extern int dlclose(void *);
            static void close_other(void *p) { record_event(2); dlclose(p); record_event(3); }
            long install(void *p) { return __cxa_atexit(close_other, p, &token); }
        "#);
        let p = f.compile("closer", &text, false, &[&s]); let h = loader.load(&p, libc::RTLD_NOW);
        assert_eq!(loader.arg(h, "install", victim as usize), 0); loader.close(h);
        assert_eq!(loader.value(sink, "events"), 234); loader.close(sink);
    }
}

#[test]
fn native_cxa_invalid_registration_and_failed_load_leave_no_callbacks() {
    if !child("native_cxa_invalid_registration_and_failed_load_leave_no_callbacks") { return; }
    let loader = Loader::Native; let f = Fixture::new(); let s = f.sink(); let sink = loader.load(&s, libc::RTLD_NOW);
    let text = format!("{API}\n{}", r#"
        long invalid(void) {
            if (__cxa_atexit(0, 0, &token) == 0) return 1;
            if (__cxa_atexit(emit, 0, (void *)1) == 0) return 2;
            if (__cxa_atexit((void (*)(void *))&token, 0, &token) == 0) return 3;
            return 0;
        }
    "#);
    let p = f.compile("valid", &text, false, &[&s]); let h = loader.load(&p, libc::RTLD_NOW);
    assert_eq!(loader.value(h, "invalid"), 0); assert_eq!(loader.arg(h, "add", 7), 0);
    let broken = f.compile("broken", r#"
        extern "C" void record_event(long); extern "C" void missing_cxa_function(void);
        struct Object { Object() { record_event(1); } ~Object() { record_event(2); } } object;
        extern "C" void failure(void) { missing_cxa_function(); }
    "#, true, &[&s]);
    assert!(loader.open(&broken, libc::RTLD_NOW).is_null()); assert!(!unsafe { dlerror() }.is_null());
    assert_eq!(loader.value(sink, "calls"), 0); loader.close(h);
    assert_eq!(loader.value(sink, "events"), 7); loader.close(sink);
}
