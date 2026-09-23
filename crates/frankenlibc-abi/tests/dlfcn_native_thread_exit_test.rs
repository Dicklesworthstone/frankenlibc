#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{dlclose, dlopen, dlsym, native_dso_handle_for_tests};
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

#[derive(Clone, Copy)]
enum Loader { Native, Host }
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
            assert!(native_dso_handle_for_tests(handle), "host fallback is not native execution");
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
    fn symbol(self, handle: *mut c_void, name: &str) -> *mut c_void {
        let name = CString::new(name).unwrap();
        let symbol = unsafe {
            match self {
                Self::Native => dlsym(handle, name.as_ptr()),
                Self::Host => {
                    let lookup: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void =
                        dlsym_oracle::host_fn(c"dlsym", dlsym as *const ());
                    lookup(handle, name.as_ptr())
                }
            }
        };
        assert!(!symbol.is_null(), "missing {name:?}");
        symbol
    }
    fn value(self, handle: *mut c_void, name: &str) -> i64 {
        let function: unsafe extern "C" fn() -> i64 = unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { function() }
    }
}

struct Fixture { dir: PathBuf, prefix: String }
impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let prefix = format!("fl_thread_exit_{}_{stamp}", std::process::id());
        let dir = std::env::temp_dir().join(&prefix);
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir, prefix }
    }
    fn name(&self, name: &str) -> String { name.replace("event_push", &format!("{}_push", self.prefix)) }
    fn compile(&self, name: &str, source: &str, cpp: bool) -> PathBuf {
        let source_path = self.dir.join(format!("{name}.{}", if cpp { "cc" } else { "c" }));
        let library = self.dir.join(format!("{name}.so"));
        std::fs::write(&source_path, self.name(source)).unwrap();
        let mut command = Command::new(if cpp { "c++" } else { "cc" });
        command.args(["-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=none"]);
        if cpp { command.args(["-fno-exceptions", "-fno-rtti", "-fno-gnu-unique"]); }
        let output = command.arg(&source_path).arg("-o").arg(&library).output().unwrap();
        assert!(output.status.success(), "compiler failed: {}", String::from_utf8_lossy(&output.stderr));
        library
    }
    fn sink(&self, loader: Loader) -> *mut c_void {
        let path = self.compile("sink", "static long values[128], count; void event_push(long x){long i=__atomic_fetch_add(&count,1,__ATOMIC_SEQ_CST); if(i<128) values[i]=x;} long event_count(void){return count;} long event_get(long i){return values[i];}", false);
        let handle = loader.open(&path, libc::RTLD_NOW | libc::RTLD_GLOBAL);
        assert!(!handle.is_null()); handle
    }
    fn events(&self, loader: Loader, sink: *mut c_void) -> Vec<i64> {
        let count = loader.value(sink, "event_count"); assert!((0..=128).contains(&count));
        let get: unsafe extern "C" fn(i64) -> i64 = unsafe { std::mem::transmute(loader.symbol(sink, "event_get")) };
        (0..count).map(|index| unsafe { get(index) }).collect()
    }
}

fn child_case(name: &str) -> bool {
    if std::env::var("FL_THREAD_EXIT_CHILD").as_deref() == Ok(name) { return true; }
    let mut child = Command::new(std::env::current_exe().unwrap()).args(["--exact", name, "--nocapture"])
        .env("FL_THREAD_EXIT_CHILD", name).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "thread-exit child {name} failed: {status}"); return false;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap(); let _ = child.wait(); panic!("thread-exit callback deadlock in {name}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// Compile real C++ thread_local objects. The tiny hidden shim provides the
// libstdc++ registration bridge without pulling a host runtime dependency into
// the native DSO. Constructors, guards and destructor registrations are all
// compiler-generated, not manually simulated by the Rust test.
const CPP: &str = r#"
    extern "C" {
        void event_push(long);
        int __cxa_thread_atexit_impl(void(*)(void*),void*,void*);
        __attribute__((visibility("hidden"))) void *__dso_handle=&__dso_handle;
        __attribute__((visibility("hidden"))) int __cxa_thread_atexit(void(*fn)(void*),void*arg,void*owner){
            return __cxa_thread_atexit_impl(fn,arg,owner);
        }
    }
    static __thread long marker=50;
    struct Item { long value; Item(long x):value(x){event_push(x);} ~Item(){event_push(-value);event_push(marker);} };
    static thread_local Item first(1),second(2);
    extern "C" long touch(void){marker=73;return first.value+second.value;}
    __attribute__((destructor)) static void fini(void){event_push(99);}
"#;

#[test]
fn native_cpp_tls_destructors_read_tls_and_run_once_in_lifo_order() {
    if !child_case("native_cpp_tls_destructors_read_tls_and_run_once_in_lifo_order") { return; }
    for loader in [Loader::Host, Loader::Native] {
        let f=Fixture::new(); let sink=f.sink(loader); let path=f.compile("cpp",CPP,true);
        let h=loader.open(&path,libc::RTLD_NOW); assert!(!h.is_null(),"C++ TLS destructor fixture rejected");
        let address=h as usize;
        std::thread::spawn(move||{
            assert_eq!(loader.value(address as *mut c_void,"touch"),3);
            assert_eq!(loader.value(address as *mut c_void,"touch"),3);
        }).join().unwrap();
        assert_eq!(f.events(loader,sink),[1,2,-2,73,-1,73]);
        loader.close(h); assert_eq!(f.events(loader,sink),[1,2,-2,73,-1,73,99]); loader.close(sink);
    }
}

#[test]
fn native_cpp_tls_pending_destructors_pin_closed_library() {
    if !child_case("native_cpp_tls_pending_destructors_pin_closed_library") { return; }
    for loader in [Loader::Host,Loader::Native] {
        let f=Fixture::new(); let sink=f.sink(loader); let path=f.compile("cpp",CPP,true);
        let h=loader.open(&path,libc::RTLD_NOW); assert!(!h.is_null());
        let gate=Arc::new(Barrier::new(2)); let worker_gate=gate.clone(); let address=h as usize;
        let worker=std::thread::spawn(move||{
            assert_eq!(loader.value(address as *mut c_void,"touch"),3);
            worker_gate.wait(); worker_gate.wait();
        });
        gate.wait(); loader.close(h); assert_eq!(f.events(loader,sink),[1,2]);
        let retained=loader.open(&path,libc::RTLD_NOW|libc::RTLD_NOLOAD); assert_eq!(retained,h); loader.close(retained);
        gate.wait(); worker.join().unwrap();
        assert_eq!(f.events(loader,sink),[1,2,-2,73,-1,73]);
        // Host releases TLS pins at thread exit, but defers library finalizers
        // until the next dlclose collection. Native must not unload mid-drain.
        let retained=loader.open(&path,libc::RTLD_NOW|libc::RTLD_NOLOAD); assert_eq!(retained,h); loader.close(retained);
        assert_eq!(f.events(loader,sink),[1,2,-2,73,-1,73,99]);
        assert!(loader.open(&path,libc::RTLD_NOW|libc::RTLD_NOLOAD).is_null()); loader.close(sink);
    }
}

#[test]
fn native_tls_destructors_can_register_more_destructors() {
    if !child_case("native_tls_destructors_can_register_more_destructors") { return; }
    for loader in [Loader::Host,Loader::Native] {
        let f=Fixture::new(); let sink=f.sink(loader);
        let path=f.compile("nested",r#"
            extern void event_push(long); extern int __cxa_thread_atexit_impl(void(*)(void*),void*,void*);
            static int owner; static __thread long value=1;
            static void end(void*p){event_push(*(long*)p);}
            static void first(void*p){event_push(value*10+1);value=3;if(__cxa_thread_atexit_impl(end,p,&owner))event_push(900);}
            long start(void){value=2;int a=__cxa_thread_atexit_impl(end,&value,&owner);int b=__cxa_thread_atexit_impl(first,&value,&owner);return a|b;}
            __attribute__((destructor)) static void fini(void){event_push(99);}
        "#,false);
        let h=loader.open(&path,libc::RTLD_NOW); assert!(!h.is_null()); let address=h as usize;
        std::thread::spawn(move||{assert_eq!(loader.value(address as *mut c_void,"start"),0);}).join().unwrap();
        assert_eq!(f.events(loader,sink),[21,3,3]); loader.close(h);
        assert_eq!(f.events(loader,sink),[21,3,3,99]); loader.close(sink);
    }
}

#[test]
fn native_tls_destructor_pins_distinct_code_and_data_providers() {
    if !child_case("native_tls_destructor_pins_distinct_code_and_data_providers") { return; }
    // This case strengthens the host contract: no DT_NEEDED or relocation edge
    // connects the modules, because the callback address is passed at runtime.
    let loader=Loader::Native; let f=Fixture::new(); let sink=f.sink(loader);
    let data_path=f.compile("data",r#"
        extern void event_push(long); extern int __cxa_thread_atexit_impl(void(*)(void*),void*,void*);
        static int owner; static __thread long value=23;
        long start(void(*callback)(void*)){return __cxa_thread_atexit_impl(callback,&value,&owner);}
        __attribute__((destructor)) static void fini(void){event_push(40);}
    "#,false);
    let code_path=f.compile("code",r#"
        extern void event_push(long); static __thread long first_used_during_exit=9;
        void callback(void*p){event_push(*(long*)p+first_used_during_exit);}
        __attribute__((destructor)) static void fini(void){event_push(50);}
    "#,false);
    let data=loader.open(&data_path,libc::RTLD_NOW); let code=loader.open(&code_path,libc::RTLD_NOW);
    assert!(!data.is_null()&&!code.is_null());
    let start=loader.symbol(data,"start") as usize; let callback=loader.symbol(code,"callback") as usize;
    let gate=Arc::new(Barrier::new(2)); let worker_gate=gate.clone();
    let worker=std::thread::spawn(move||{
        let start:unsafe extern "C" fn(*mut c_void)->i64=unsafe{std::mem::transmute(start)};
        assert_eq!(unsafe{start(callback as *mut c_void)},0);
        worker_gate.wait(); worker_gate.wait();
    });
    gate.wait(); loader.close(data); loader.close(code); assert!(f.events(loader,sink).is_empty());
    assert!(native_dso_handle_for_tests(data)); assert!(native_dso_handle_for_tests(code));
    gate.wait(); worker.join().unwrap(); assert_eq!(f.events(loader,sink),[32]);
    let data_ref=loader.open(&data_path,libc::RTLD_NOW|libc::RTLD_NOLOAD); assert_eq!(data_ref,data);
    let code_ref=loader.open(&code_path,libc::RTLD_NOW|libc::RTLD_NOLOAD); assert_eq!(code_ref,code);
    loader.close(data_ref); loader.close(code_ref); assert_eq!(f.events(loader,sink),[32,40,50]); loader.close(sink);
}

#[test]
fn native_tls_destructor_registration_rejects_invalid_owners_and_code() {
    if !child_case("native_tls_destructor_registration_rejects_invalid_owners_and_code") { return; }
    let loader=Loader::Native; let f=Fixture::new(); let sink=f.sink(loader);
    let path=f.compile("invalid",r#"
        extern void event_push(long); extern int __cxa_thread_atexit_impl(void(*)(void*),void*,void*);
        static int owner; static void end(void*p){event_push(7);}
        long check(void){
            if(__cxa_thread_atexit_impl(0,0,&owner)!=-1)return 1;
            if(__cxa_thread_atexit_impl(end,0,0)!=-1)return 2;
            if(__cxa_thread_atexit_impl((void(*)(void*))&owner,0,&owner)!=-1)return 3;
            return __cxa_thread_atexit_impl(end,0,&owner);
        }
        __attribute__((destructor)) static void fini(void){event_push(99);}
    "#,false);
    let h=loader.open(&path,libc::RTLD_NOW); assert!(!h.is_null()); let address=h as usize;
    std::thread::spawn(move||{assert_eq!(loader.value(address as *mut c_void,"check"),0);}).join().unwrap();
    assert_eq!(f.events(loader,sink),[7]); loader.close(h); assert_eq!(f.events(loader,sink),[7,99]);
    assert!(loader.open(&path,libc::RTLD_NOW|libc::RTLD_NOLOAD).is_null()); loader.close(sink);
}
