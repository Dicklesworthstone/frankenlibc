#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{dlclose, dlerror, dlopen, dlsym, native_dso_handle_for_tests};
use frankenlibc_abi::pthread_abi;
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

// The native workers in the new protocols execute only compiled fixture code
// and owned TLS teardown. A Rust heap call there would reach System/host malloc
// through inherited hardware TLS, even when an ordinary test happened to pass.
static REJECT_NATIVE_HEAP: AtomicBool = AtomicBool::new(false);
// Keep auditing detached cleanup after the native identity table retires it.
static REJECT_NATIVE_TID: AtomicI32 = AtomicI32::new(0);
struct AuditedAllocator;

fn check_native_heap() {
    if !REJECT_NATIVE_HEAP.load(Ordering::Relaxed) {
        return;
    }
    let detached_tid = REJECT_NATIVE_TID.load(Ordering::Acquire);
    if frankenlibc_core::pthread::thread::current_thread_handle().is_some()
        || (detached_tid > 0 && frankenlibc_core::syscall::sys_gettid() == detached_tid)
    {
        frankenlibc_core::syscall::sys_exit_group(93);
    }
}

// SAFETY: every permitted allocation is forwarded unchanged to System. The
// rejected native path terminates before touching the host allocator.
unsafe impl GlobalAlloc for AuditedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        check_native_heap();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        check_native_heap();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        check_native_heap();
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        check_native_heap();
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: AuditedAllocator = AuditedAllocator;

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
                "host fallback is not native execution"
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
        let function: unsafe extern "C" fn() -> i64 =
            unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { function() }
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
        let prefix = format!("fl_thread_exit_{}_{stamp}", std::process::id());
        let dir = std::env::temp_dir().join(&prefix);
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir, prefix }
    }
    fn name(&self, name: &str) -> String {
        name.replace("event_push", &format!("{}_push", self.prefix))
    }
    fn compile(&self, name: &str, source: &str, cpp: bool) -> PathBuf {
        self.compile_with_flags(name, source, cpp, &[])
    }
    fn compile_with_flags(&self, name: &str, source: &str, cpp: bool, flags: &[&str]) -> PathBuf {
        let source_path = self
            .dir
            .join(format!("{name}.{}", if cpp { "cc" } else { "c" }));
        let library = self.dir.join(format!("{name}.so"));
        std::fs::write(&source_path, self.name(source)).unwrap();
        let mut command = Command::new(if cpp { "c++" } else { "cc" });
        command.args(["-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=none"]);
        if cpp {
            command.args(["-fno-exceptions", "-fno-rtti", "-fno-gnu-unique"]);
        }
        command.args(flags);
        let output = command
            .arg(&source_path)
            .arg("-o")
            .arg(&library)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "compiler failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        library
    }
    fn sink(&self, loader: Loader) -> *mut c_void {
        let path = self.compile("sink", "static long values[128], count; void event_push(long x){long i=__atomic_fetch_add(&count,1,__ATOMIC_SEQ_CST); if(i<128) values[i]=x;} long event_count(void){return count;} long event_get(long i){return values[i];}", false);
        let handle = loader.open(&path, libc::RTLD_NOW | libc::RTLD_GLOBAL);
        assert!(!handle.is_null());
        handle
    }
    fn events(&self, loader: Loader, sink: *mut c_void) -> Vec<i64> {
        let count = loader.value(sink, "event_count");
        assert!((0..=128).contains(&count));
        let get: unsafe extern "C" fn(i64) -> i64 =
            unsafe { std::mem::transmute(loader.symbol(sink, "event_get")) };
        (0..count).map(|index| unsafe { get(index) }).collect()
    }
}

fn child_case(name: &str) -> bool {
    if std::env::var("FL_THREAD_EXIT_CHILD").as_deref() == Ok(name) {
        return true;
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("FL_THREAD_EXIT_CHILD", name)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                status.success(),
                "thread-exit child {name} failed: {status}"
            );
            return false;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("thread-exit callback deadlock in {name}");
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
    if !child_case("native_cpp_tls_destructors_read_tls_and_run_once_in_lifo_order") {
        return;
    }
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let sink = f.sink(loader);
        let path = f.compile("cpp", CPP, true);
        let h = loader.open(&path, libc::RTLD_NOW);
        assert!(!h.is_null(), "C++ TLS destructor fixture rejected");
        let address = h as usize;
        std::thread::spawn(move || {
            assert_eq!(loader.value(address as *mut c_void, "touch"), 3);
            assert_eq!(loader.value(address as *mut c_void, "touch"), 3);
        })
        .join()
        .unwrap();
        assert_eq!(f.events(loader, sink), [1, 2, -2, 73, -1, 73]);
        loader.close(h);
        assert_eq!(f.events(loader, sink), [1, 2, -2, 73, -1, 73, 99]);
        loader.close(sink);
    }
}

#[test]
fn native_cpp_tls_pending_destructors_pin_closed_library() {
    if !child_case("native_cpp_tls_pending_destructors_pin_closed_library") {
        return;
    }
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let sink = f.sink(loader);
        let path = f.compile("cpp", CPP, true);
        let h = loader.open(&path, libc::RTLD_NOW);
        assert!(!h.is_null());
        let gate = Arc::new(Barrier::new(2));
        let worker_gate = gate.clone();
        let address = h as usize;
        let worker = std::thread::spawn(move || {
            assert_eq!(loader.value(address as *mut c_void, "touch"), 3);
            worker_gate.wait();
            worker_gate.wait();
        });
        gate.wait();
        loader.close(h);
        assert_eq!(f.events(loader, sink), [1, 2]);
        let retained = loader.open(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD);
        assert_eq!(retained, h);
        loader.close(retained);
        gate.wait();
        worker.join().unwrap();
        assert_eq!(f.events(loader, sink), [1, 2, -2, 73, -1, 73]);
        // Host releases TLS pins at thread exit, but defers library finalizers
        // until the next dlclose collection. Native must not unload mid-drain.
        let retained = loader.open(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD);
        assert_eq!(retained, h);
        loader.close(retained);
        assert_eq!(f.events(loader, sink), [1, 2, -2, 73, -1, 73, 99]);
        assert!(
            loader
                .open(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD)
                .is_null()
        );
        loader.close(sink);
    }
}

#[test]
fn native_tls_destructors_can_register_more_destructors() {
    if !child_case("native_tls_destructors_can_register_more_destructors") {
        return;
    }
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let sink = f.sink(loader);
        let path=f.compile("nested",r#"
            extern void event_push(long); extern int __cxa_thread_atexit_impl(void(*)(void*),void*,void*);
            static int owner; static __thread long value=1;
            static void end(void*p){event_push(*(long*)p);}
            static void first(void*p){event_push(value*10+1);value=3;if(__cxa_thread_atexit_impl(end,p,&owner))event_push(900);}
            long start(void){value=2;int a=__cxa_thread_atexit_impl(end,&value,&owner);int b=__cxa_thread_atexit_impl(first,&value,&owner);return a|b;}
            __attribute__((destructor)) static void fini(void){event_push(99);}
        "#,false);
        let h = loader.open(&path, libc::RTLD_NOW);
        assert!(!h.is_null());
        let address = h as usize;
        std::thread::spawn(move || {
            assert_eq!(loader.value(address as *mut c_void, "start"), 0);
        })
        .join()
        .unwrap();
        assert_eq!(f.events(loader, sink), [21, 3, 3]);
        loader.close(h);
        assert_eq!(f.events(loader, sink), [21, 3, 3, 99]);
        loader.close(sink);
    }
}

#[test]
fn native_tls_destructor_pins_distinct_code_and_data_providers() {
    if !child_case("native_tls_destructor_pins_distinct_code_and_data_providers") {
        return;
    }
    // This case strengthens the host contract: no DT_NEEDED or relocation edge
    // connects the modules, because the callback address is passed at runtime.
    let loader = Loader::Native;
    let f = Fixture::new();
    let sink = f.sink(loader);
    let data_path=f.compile("data",r#"
        extern void event_push(long); extern int __cxa_thread_atexit_impl(void(*)(void*),void*,void*);
        static int owner; static __thread long value=23;
        long start(void(*callback)(void*)){return __cxa_thread_atexit_impl(callback,&value,&owner);}
        __attribute__((destructor)) static void fini(void){event_push(40);}
    "#,false);
    let code_path = f.compile(
        "code",
        r#"
        extern void event_push(long); static __thread long first_used_during_exit=9;
        void callback(void*p){event_push(*(long*)p+first_used_during_exit);}
        __attribute__((destructor)) static void fini(void){event_push(50);}
    "#,
        false,
    );
    let data = loader.open(&data_path, libc::RTLD_NOW);
    let code = loader.open(&code_path, libc::RTLD_NOW);
    assert!(!data.is_null() && !code.is_null());
    let start = loader.symbol(data, "start") as usize;
    let callback = loader.symbol(code, "callback") as usize;
    let gate = Arc::new(Barrier::new(2));
    let worker_gate = gate.clone();
    let worker = std::thread::spawn(move || {
        let start: unsafe extern "C" fn(*mut c_void) -> i64 = unsafe { std::mem::transmute(start) };
        assert_eq!(unsafe { start(callback as *mut c_void) }, 0);
        worker_gate.wait();
        worker_gate.wait();
    });
    gate.wait();
    loader.close(data);
    loader.close(code);
    assert!(f.events(loader, sink).is_empty());
    assert!(native_dso_handle_for_tests(data));
    assert!(native_dso_handle_for_tests(code));
    gate.wait();
    worker.join().unwrap();
    assert_eq!(f.events(loader, sink), [32]);
    let data_ref = loader.open(&data_path, libc::RTLD_NOW | libc::RTLD_NOLOAD);
    assert_eq!(data_ref, data);
    let code_ref = loader.open(&code_path, libc::RTLD_NOW | libc::RTLD_NOLOAD);
    assert_eq!(code_ref, code);
    loader.close(data_ref);
    loader.close(code_ref);
    assert_eq!(f.events(loader, sink), [32, 40, 50]);
    loader.close(sink);
}

#[test]
fn native_tls_destructor_registration_rejects_invalid_owners_and_code() {
    if !child_case("native_tls_destructor_registration_rejects_invalid_owners_and_code") {
        return;
    }
    let loader = Loader::Native;
    let f = Fixture::new();
    let sink = f.sink(loader);
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
    let h = loader.open(&path, libc::RTLD_NOW);
    assert!(!h.is_null());
    let address = h as usize;
    std::thread::spawn(move || {
        assert_eq!(loader.value(address as *mut c_void, "check"), 0);
    })
    .join()
    .unwrap();
    assert_eq!(f.events(loader, sink), [7]);
    loader.close(h);
    assert_eq!(f.events(loader, sink), [7, 99]);
    assert!(
        loader
            .open(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD)
            .is_null()
    );
    loader.close(sink);
}

const NATIVE_WORKERS: usize = 8;
const CONCURRENT_CPP_TLS: &str = r#"
    #include <pthread.h>
    #include <stdint.h>
    #include <errno.h>
    extern "C" {
        void event_push(long);
        int __cxa_thread_atexit_impl(void(*)(void*),void*,void*);
        __attribute__((visibility("hidden"))) void *__dso_handle=&__dso_handle;
        __attribute__((visibility("hidden"))) int __cxa_thread_atexit(void(*fn)(void*),void*arg,void*owner){
            return __cxa_thread_atexit_impl(fn,arg,owner);
        }
    }
    static __thread long marker=17;
    static __thread long local_value __attribute__((tls_model("local-dynamic")))=29;
    static __thread long aligned_value __attribute__((aligned(8192)))=23;
    static __thread unsigned char zeroed[64];
    static __thread long arguments[12];
    static uintptr_t addresses[9][4], owners[8];
    static unsigned arrived, released, errors, exit_mode;
    static void check(int condition){if(!condition)__atomic_fetch_add(&errors,1,__ATOMIC_RELAXED);}
    struct Item {
        long tag;
        Item(long value):tag(value){}
        ~Item(){event_push(marker*100+tag);}
    };
    static thread_local Item first(1), second(2);
    static void nested(void *pointer){event_push(9000+*(long*)pointer);}
    static void callback(void *pointer){
        long value=*(long*)pointer;
        event_push(value);
        if(value%100==11)check(__cxa_thread_atexit_impl(nested,&marker,__dso_handle)==0);
    }
    static void save_addresses(unsigned index){
        addresses[index][0]=(uintptr_t)&marker;
        addresses[index][1]=(uintptr_t)&local_value;
        addresses[index][2]=(uintptr_t)&aligned_value;
        addresses[index][3]=(uintptr_t)&zeroed;
    }
    extern "C" long warm_parent(void){
        check(marker==17 && local_value==29 && aligned_value==23 && zeroed[0]==0);
        marker=601;local_value=602;aligned_value=603;zeroed[0]=77;
        save_addresses(8);return 0;
    }
    extern "C" long parent_ok(void){
        return marker==601 && local_value==602 && aligned_value==603 && zeroed[0]==77;
    }
    extern "C" void select_exit(unsigned value){exit_mode=value;}
    extern "C" void *worker(void *argument){
        unsigned id=(unsigned)(uintptr_t)argument;
        check(marker==17 && local_value==29 && aligned_value==23);
        for(unsigned i=0;i<64;i++)check(zeroed[i]==0);
        check(((uintptr_t)&aligned_value&8191)==0);
        errno=700+(int)id;
        marker=id;local_value=100+(long)id;aligned_value=200+(long)id;zeroed[0]=(unsigned char)id;
        check(first.tag+second.tag==3);
        for(unsigned i=0;i<12;i++){
            arguments[i]=1000+(long)id*100+i;
            check(__cxa_thread_atexit_impl(callback,&arguments[i],__dso_handle)==0);
        }
        save_addresses(id-1);
        owners[id-1]=(uintptr_t)pthread_self();
        __atomic_fetch_add(&arrived,1,__ATOMIC_RELEASE);
        while(!__atomic_load_n(&released,__ATOMIC_ACQUIRE)){}
        check(marker==(long)id && local_value==100+(long)id && aligned_value==200+(long)id);
        check(zeroed[0]==id && errno==700+(int)id);
        if(exit_mode==1)pthread_exit(argument);
        if(exit_mode==2){pthread_cancel(pthread_self());pthread_testcancel();return (void*)999;}
        return argument;
    }
    extern "C" unsigned ready(void){return __atomic_load_n(&arrived,__ATOMIC_ACQUIRE);}
    extern "C" void release_workers(void){__atomic_store_n(&released,1,__ATOMIC_RELEASE);}
    extern "C" unsigned failure_count(void){return __atomic_load_n(&errors,__ATOMIC_RELAXED);}
    extern "C" uintptr_t slot_address(unsigned thread,unsigned slot){return addresses[thread][slot];}
    extern "C" uintptr_t owner(unsigned thread){return owners[thread];}
    __attribute__((destructor)) static void fini(void){event_push(99);}
"#;

type StartRoutine = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type CreateThread = unsafe extern "C" fn(
    *mut libc::pthread_t,
    *const libc::pthread_attr_t,
    Option<StartRoutine>,
    *mut c_void,
) -> c_int;
type JoinThread = unsafe extern "C-unwind" fn(libc::pthread_t, *mut *mut c_void) -> c_int;

fn thread_backend(loader: Loader) -> (CreateThread, JoinThread) {
    match loader {
        Loader::Native => {
            pthread_abi::pthread_threading_force_native_for_tests();
            (pthread_abi::pthread_create, pthread_abi::pthread_join)
        }
        // SAFETY: these signatures match the resolved host pthread ABIs;
        // host_fn rejects an oracle that aliases FrankenLibC's definitions.
        Loader::Host => unsafe {
            (
                dlsym_oracle::host_fn(c"pthread_create", pthread_abi::pthread_create as *const ()),
                dlsym_oracle::host_fn(c"pthread_join", pthread_abi::pthread_join as *const ()),
            )
        },
    }
}

fn concurrent_native_tls_protocol(exit_mode: u32) {
    for loader in [Loader::Host, Loader::Native] {
        for dialect in ["gnu", "gnu2"] {
            let fixture = Fixture::new();
            let sink = fixture.sink(loader);
            let flag = format!("-mtls-dialect={dialect}");
            let path = fixture.compile_with_flags("concurrent", CONCURRENT_CPP_TLS, true, &[&flag, "-O2"]);
            let object = frankenlibc_core::elf::ElfLoader::new(0)
                .parse(&std::fs::read(&path).unwrap()).unwrap();
            assert!(object.needed_libraries.is_empty(), "fixture acquired a host dependency");
            assert!(object.tls_segment.is_some());
            if dialect == "gnu2" {
                assert!(object.rela_dyn.iter().chain(&object.rela_plt)
                    .any(|relocation| relocation.reloc_type().to_u32() == 36),
                    "GNU2 fixture emitted no TLSDESC relocation");
            }
            let handle = loader.open(&path, libc::RTLD_NOW);
            assert!(!handle.is_null());
            assert_eq!(loader.value(handle, "warm_parent"), 0);
            let worker: StartRoutine = unsafe { std::mem::transmute(loader.symbol(handle, "worker")) };
            let ready: unsafe extern "C" fn() -> u32 = unsafe { std::mem::transmute(loader.symbol(handle, "ready")) };
            let release: unsafe extern "C" fn() = unsafe { std::mem::transmute(loader.symbol(handle, "release_workers")) };
            let select_exit: unsafe extern "C" fn(u32) = unsafe { std::mem::transmute(loader.symbol(handle, "select_exit")) };
            let failures: unsafe extern "C" fn() -> u32 = unsafe { std::mem::transmute(loader.symbol(handle, "failure_count")) };
            let address: unsafe extern "C" fn(u32, u32) -> usize = unsafe { std::mem::transmute(loader.symbol(handle, "slot_address")) };
            let owner: unsafe extern "C" fn(u32) -> usize = unsafe { std::mem::transmute(loader.symbol(handle, "owner")) };
            let (create, join) = thread_backend(loader);
            unsafe { select_exit(exit_mode) };
            let mut threads = [0 as libc::pthread_t; NATIVE_WORKERS];
            REJECT_NATIVE_HEAP.store(true, Ordering::Release);
            for (index, thread) in threads.iter_mut().enumerate() {
                assert_eq!(unsafe { create(thread, std::ptr::null(), Some(worker), (index + 1) as *mut c_void) }, 0);
            }
            while unsafe { ready() } != NATIVE_WORKERS as u32 {
                std::thread::sleep(Duration::from_millis(1));
            }
            // All callbacks are pinned before close. Both GNU and native
            // loaders must retain code/data until each real worker exits.
            loader.close(handle);
            let retained = loader.open(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD);
            assert_eq!(retained, handle);
            loader.close(retained);
            unsafe { release() };
            let mut values = [std::ptr::null_mut(); NATIVE_WORKERS];
            for (index, thread) in threads.iter().enumerate() {
                assert_eq!(unsafe { join(*thread, &mut values[index]) }, 0);
            }
            REJECT_NATIVE_HEAP.store(false, Ordering::Release);
            assert_eq!(unsafe { failures() }, 0, "TLS/errno/template isolation failed for {dialect}");
            assert_eq!(loader.value(handle, "parent_ok"), 1);
            for (index, thread) in threads.iter().enumerate() {
                assert_eq!(unsafe { owner(index as u32) }, *thread as usize);
                assert_eq!(values[index] as usize, if exit_mode == 2 { usize::MAX } else { index + 1 });
                for slot in 0..4 {
                    let own = unsafe { address(index as u32, slot) };
                    assert_ne!(own, 0);
                    assert_ne!(own, unsafe { address(NATIVE_WORKERS as u32, slot) });
                    for previous in 0..index {
                        assert_ne!(own, unsafe { address(previous as u32, slot) });
                    }
                }
            }
            let events = fixture.events(loader, sink);
            assert_eq!(events.len(), NATIVE_WORKERS * 15);
            for id in 1..=NATIVE_WORKERS as i64 {
                let own: Vec<_> = events.iter().copied().filter(|value| {
                    if *value >= 9000 { *value - 9000 == id }
                    else if *value >= 1000 { (*value - 1000) / 100 == id }
                    else { *value / 100 == id }
                }).collect();
                let mut expected = vec![1000 + id * 100 + 11, 9000 + id];
                expected.extend((0..11).rev().map(|offset| 1000 + id * 100 + offset));
                expected.extend([id * 100 + 2, id * 100 + 1]);
                assert_eq!(own, expected, "thread {id}: C++ TLS destructor order");
            }
            let retained = loader.open(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD);
            assert_eq!(retained, handle);
            loader.close(retained);
            let events = fixture.events(loader, sink);
            assert_eq!(events.len(), NATIVE_WORKERS * 15 + 1);
            assert_eq!(events.last(), Some(&99));
            assert!(loader.open(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
            loader.close(sink);
        }
    }
}

#[test]
fn native_clone_dynamic_tls_and_cpp_destructors_on_return() {
    if child_case("native_clone_dynamic_tls_and_cpp_destructors_on_return") {
        concurrent_native_tls_protocol(0);
    }
}

#[test]
fn native_clone_dynamic_tls_and_cpp_destructors_on_pthread_exit() {
    if child_case("native_clone_dynamic_tls_and_cpp_destructors_on_pthread_exit") {
        concurrent_native_tls_protocol(1);
    }
}

#[test]
fn native_clone_dynamic_tls_and_cpp_destructors_on_cancellation() {
    if child_case("native_clone_dynamic_tls_and_cpp_destructors_on_cancellation") {
        concurrent_native_tls_protocol(2);
    }
}

struct ReloadProbe {
    first: unsafe extern "C" fn() -> *mut i64,
    replacement: AtomicUsize,
    phase: AtomicU32,
}

unsafe extern "C" fn reload_worker(argument: *mut c_void) -> *mut c_void {
    // SAFETY: the parent retains the probe until join, and waits until the
    // first DSO call has returned before unloading that code and template.
    let probe = unsafe { &*argument.cast::<ReloadProbe>() };
    let first = unsafe { (probe.first)() };
    let mut failure = if first.is_null() || unsafe { *first } != 17 { 1 } else { 0 };
    if !first.is_null() {
        unsafe { *first = 41 };
    }
    probe.phase.store(1, Ordering::Release);
    while probe.phase.load(Ordering::Acquire) != 2 {
        std::hint::spin_loop();
    }
    let replacement: unsafe extern "C" fn() -> *mut i64 =
        unsafe { std::mem::transmute(probe.replacement.load(Ordering::Acquire)) };
    let next = unsafe { replacement() };
    if next.is_null() || unsafe { *next } != 17 {
        failure = 2;
    }
    failure as *mut c_void
}

#[test]
fn native_clone_tls_unload_reload_prunes_without_host_heap_reclamation() {
    if !child_case("native_clone_tls_unload_reload_prunes_without_host_heap_reclamation") {
        return;
    }
    let fixture = Fixture::new();
    let path = fixture.compile("reload", r#"
        static __thread long value=17;
        long *tls_address(void){return &value;}
    "#, false);
    let loader = Loader::Native;
    let first = loader.open(&path, libc::RTLD_NOW);
    assert!(!first.is_null());
    let probe = ReloadProbe {
        first: unsafe { std::mem::transmute(loader.symbol(first, "tls_address")) },
        replacement: AtomicUsize::new(0),
        phase: AtomicU32::new(0),
    };
    let (create, join) = thread_backend(loader);
    let mut thread = 0;
    REJECT_NATIVE_HEAP.store(true, Ordering::Release);
    assert_eq!(unsafe {
        create(&mut thread, std::ptr::null(), Some(reload_worker), std::ptr::from_ref(&probe).cast_mut().cast())
    }, 0);
    while probe.phase.load(Ordering::Acquire) != 1 {
        std::thread::sleep(Duration::from_millis(1));
    }
    loader.close(first);
    assert!(!native_dso_handle_for_tests(first));
    let replacement = loader.open(&path, libc::RTLD_NOW);
    assert!(!replacement.is_null());
    assert_ne!(first, replacement, "native module IDs must not be reused");
    probe.replacement.store(loader.symbol(replacement, "tls_address") as usize, Ordering::Release);
    probe.phase.store(2, Ordering::Release);
    let mut result = std::ptr::null_mut();
    assert_eq!(unsafe { join(thread, &mut result) }, 0);
    REJECT_NATIVE_HEAP.store(false, Ordering::Release);
    assert!(result.is_null(), "reloaded TLS reused an expired template: {result:?}");
    loader.close(replacement);
}

#[test]
fn native_clone_posix_keys_retain_tls_and_late_runtime_destructors() {
    if !child_case("native_clone_posix_keys_retain_tls_and_late_runtime_destructors") {
        return;
    }
    let fixture = Fixture::new();
    let loader = Loader::Native;
    let sink = fixture.sink(loader);
    let path = fixture.compile("late", r#"
        #define _GNU_SOURCE
        #include <pthread.h>
        #include <signal.h>
        #include <dlfcn.h>
        extern void event_push(long);
        extern int __cxa_thread_atexit_impl(void(*)(void*),void*,void*);
        static int owner;
        static pthread_key_t key;
        static __thread long value=31;
        static void last(void *pointer){
            sigset_t old, empty={0};
            if(pthread_sigmask(SIG_SETMASK,0,&old))event_push(901);
            if(!(((unsigned long*)&old)[0]&(1UL<<(SIGUSR1-1))))event_push(902);
            event_push(*(long*)pointer==146 ? 4 : 903);
            /* The final empty-queue check must block these again too. */
            if(pthread_sigmask(SIG_SETMASK,&empty,0))event_push(904);
        }
        static void late(void *pointer){
            sigset_t empty={0};
            event_push(*(long*)pointer==73 ? 3 : 905);
            *(long*)pointer=146;
            if(pthread_sigmask(SIG_SETMASK,&empty,0))event_push(906);
            if(__cxa_thread_atexit_impl(last,pointer,&owner))event_push(907);
        }
        static void key_destructor(void *pointer){
            event_push(*(long*)pointer==73 ? 2 : 908);
            if(__cxa_thread_atexit_impl(late,pointer,&owner))event_push(909);
        }
        static void early(void *pointer){event_push(*(long*)pointer==73 ? 1 : 910);}
        void *mask_provider(void){return (void*)pthread_sigmask;}
        long initialize(void){
            if(dlsym(RTLD_DEFAULT,"pthread_sigmask")!=(void*)pthread_sigmask)return 101;
            if(dlvsym(RTLD_DEFAULT,"pthread_sigmask","GLIBC_2.2.5")!=(void*)pthread_sigmask)return 102;
            if(dlvsym(RTLD_DEFAULT,"pthread_sigmask","GLIBC_2.32")!=(void*)pthread_sigmask)return 103;
            if(dlvsym(RTLD_DEFAULT,"pthread_sigmask","GLIBC_2.34"))return 104;
            if(!dlerror())return 105;
            return pthread_key_create(&key,key_destructor);
        }
        long finish(void){return pthread_key_delete(key);}
        void *worker(void *argument){
            (void)argument;value=73;
            if(pthread_setspecific(key,&value))return (void*)1;
            if(__cxa_thread_atexit_impl(early,&value,&owner))return (void*)2;
            return 0;
        }
    "#, false);
    let handle = loader.open(&path, libc::RTLD_NOW);
    assert!(!handle.is_null(), "late TLS fixture rejected: {:?}", unsafe {
        let error = dlerror();
        (!error.is_null()).then(|| CStr::from_ptr(error).to_string_lossy().into_owned())
    });
    let provider: unsafe extern "C" fn() -> *mut c_void =
        unsafe { std::mem::transmute(loader.symbol(handle, "mask_provider")) };
    assert_eq!(unsafe { provider() }, frankenlibc_abi::signal_abi::pthread_sigmask as *const () as *mut c_void);
    assert_eq!(loader.value(handle, "initialize"), 0);
    let worker: StartRoutine = unsafe { std::mem::transmute(loader.symbol(handle, "worker")) };
    let (create, join) = thread_backend(loader);
    let mut thread = 0;
    REJECT_NATIVE_HEAP.store(true, Ordering::Release);
    assert_eq!(unsafe { create(&mut thread, std::ptr::null(), Some(worker), std::ptr::null_mut()) }, 0);
    let mut result = std::ptr::null_mut();
    assert_eq!(unsafe { join(thread, &mut result) }, 0);
    REJECT_NATIVE_HEAP.store(false, Ordering::Release);
    assert!(result.is_null());
    assert_eq!(fixture.events(loader, sink), [1, 2, 3, 4]);
    assert_eq!(loader.value(handle, "finish"), 0);
    loader.close(handle);
    loader.close(sink);
}

#[repr(C)]
struct DetachedProbe {
    tid: AtomicI32,
    released: AtomicU32,
    callbacks_done: AtomicU32,
}

fn assert_mapping_pages(base: usize, length: usize, mapped: bool) {
    assert_ne!(base, 0);
    assert_ne!(length, 0);
    let first = base & !4095usize;
    let last = base.checked_add(length - 1).unwrap() & !4095usize;
    for page in (first..=last).step_by(4096) {
        let mut resident = 0u8;
        // SAFETY: mincore inspects numeric mapping addresses without accessing
        // their contents; one output byte covers this one-page request.
        let result = unsafe {
            frankenlibc_core::syscall::sys_mincore(page, 4096, &mut resident)
        };
        assert_eq!(result, if mapped { Ok(()) } else { Err(libc::ENOMEM) },
            "mapping page {page:#x}, expected mapped={mapped}");
    }
}

const DETACHED_CPP_TLS: &str = r#"
    extern "C" {
        void event_push(long);
        int __cxa_thread_atexit_impl(void(*)(void*),void*,void*);
        __attribute__((visibility("hidden"))) void *__dso_handle=&__dso_handle;
        __attribute__((visibility("hidden"))) int __cxa_thread_atexit(void(*fn)(void*),void*arg,void*owner){
            return __cxa_thread_atexit_impl(fn,arg,owner);
        }
    }
    struct Probe { int tid; unsigned released, callbacks_done; };
    static __thread Probe *progress;
    static __thread long value=17;
    struct Item {
        long tag;
        Item(long x):tag(x){}
        ~Item(){
            event_push(value==71 ? tag : 900+tag);
            if(tag==1)__atomic_store_n(&progress->callbacks_done,1,__ATOMIC_RELEASE);
        }
    };
    static thread_local Item first(1),second(2);
    static void manual(void *pointer){
        event_push(*(long*)pointer==71 && value==71 ? 3 : 903);
    }
    extern "C" void *worker(void *argument){
        progress=(Probe*)argument;
        value=71;
        if(first.tag+second.tag!=3)event_push(904);
        if(__cxa_thread_atexit_impl(manual,&value,__dso_handle))event_push(905);
        long tid;
        __asm__ volatile("syscall" : "=a"(tid) : "0"(186L) : "rcx","r11","memory","cc");
        __atomic_store_n(&progress->tid,(int)tid,__ATOMIC_RELEASE);
        while(!__atomic_load_n(&progress->released,__ATOMIC_ACQUIRE)){}
        return 0;
    }
    __attribute__((destructor)) static void fini(void){event_push(99);}
"#;

#[test]
fn native_detached_cpp_threads_reclaim_owned_handles_and_stacks() {
    if !child_case("native_detached_cpp_threads_reclaim_owned_handles_and_stacks") {
        return;
    }
    use frankenlibc_core::pthread::thread::{ThreadHandle, create_thread, detach_thread};
    use frankenlibc_core::syscall::{sys_getpid, sys_tgkill};

    for detach_after_exit in [false, true] {
        let fixture = Fixture::new();
        let loader = Loader::Native;
        let sink = fixture.sink(loader);
        let path = fixture.compile_with_flags("detached", DETACHED_CPP_TLS, true, &["-O2"]);
        let library = loader.open(&path, libc::RTLD_NOW);
        assert!(!library.is_null(), "detached C++ fixture rejected");
        let worker = loader.symbol(library, "worker") as usize;
        let probe = DetachedProbe {
            tid: AtomicI32::new(0),
            released: AtomicU32::new(0),
            callbacks_done: AtomicU32::new(0),
        };
        REJECT_NATIVE_HEAP.store(true, Ordering::Release);
        // SAFETY: the C entry point has the core start-routine ABI, and the
        // probe and DSO remain live until kernel-observed worker termination.
        let thread = unsafe {
            create_thread(worker, std::ptr::from_ref(&probe) as usize, 0)
        }.unwrap();
        let ready_deadline = Instant::now() + Duration::from_secs(10);
        let tid = loop {
            let tid = probe.tid.load(Ordering::Acquire);
            if tid != 0 {
                break tid;
            }
            assert!(Instant::now() < ready_deadline, "detached worker did not reach its gate");
            std::thread::sleep(Duration::from_millis(1));
        };
        assert!(tid > 0);
        REJECT_NATIVE_TID.store(tid, Ordering::Release);

        // Copy all coordinates while the joinable worker is held at its gate.
        // Never dereference its handle after either successful detach.
        let handle_address = thread as usize;
        let handle_length = std::mem::size_of::<ThreadHandle>();
        let (stack_address, stack_length, handle_tid) = unsafe {
            ((*thread).stack_base, (*thread).stack_total_size,
                (*thread).self_tid.load(Ordering::Acquire))
        };
        assert_eq!(handle_tid, tid, "fixture must execute on the native clone");
        assert_mapping_pages(handle_address, handle_length, true);
        assert_mapping_pages(stack_address, stack_length, true);
        loader.close(library);
        assert!(native_dso_handle_for_tests(library), "pending TLS callbacks must pin the DSO");
        assert!(fixture.events(loader, sink).is_empty());

        if !detach_after_exit {
            // SAFETY: the gated worker is still joinable. Core detach performs
            // no allocating ABI bookkeeping after later reclamation.
            assert_eq!(unsafe { detach_thread(thread) }, Ok(()));
        }
        probe.released.store(1, Ordering::Release);
        let death_deadline = Instant::now() + Duration::from_secs(10);
        let process = sys_getpid();
        loop {
            match sys_tgkill(process, tid, 0) {
                Err(libc::ESRCH) => break,
                Ok(()) => {}
                Err(error) => panic!("tgkill({tid}, 0) failed: {error}"),
            }
            assert!(Instant::now() < death_deadline, "detached worker remained alive");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(probe.callbacks_done.load(Ordering::Acquire), 1);
        if detach_after_exit {
            // Kernel death alone must not reclaim a joinable thread's storage.
            assert_mapping_pages(handle_address, handle_length, true);
            assert_mapping_pages(stack_address, stack_length, true);
            // SAFETY: no prior detach/join consumed this finished handle.
            assert_eq!(unsafe { detach_thread(thread) }, Ok(()));
        }
        // No allocating parent work occurs between detach/death and these
        // checks, so unrelated mappings cannot reuse the retired addresses.
        assert_mapping_pages(handle_address, handle_length, false);
        assert_mapping_pages(stack_address, stack_length, false);
        REJECT_NATIVE_HEAP.store(false, Ordering::Release);
        REJECT_NATIVE_TID.store(0, Ordering::Release);

        assert_eq!(fixture.events(loader, sink), [3, 2, 1]);
        let retained = loader.open(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD);
        assert_eq!(retained, library);
        loader.close(retained);
        assert_eq!(fixture.events(loader, sink), [3, 2, 1, 99]);
        assert!(loader.open(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
        loader.close(sink);
    }
}
