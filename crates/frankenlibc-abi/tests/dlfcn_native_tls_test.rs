#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{dlclose, dlerror, dlopen, dlsym, dlvsym, native_dso_handle_for_tests};
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

static SERIAL: Mutex<()> = Mutex::new(());

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
            assert!(native_dso_handle_for_tests(handle), "host fallback is not native TLS execution");
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
                        let lookup: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void =
                            dlsym_oracle::host_fn(c"dlsym", dlsym as *const ());
                        lookup(handle, name.as_ptr())
                    }
                },
                Some(version) => {
                    let version = CString::new(version).unwrap();
                    match self {
                        Self::Native => dlvsym(handle, name.as_ptr(), version.as_ptr()),
                        Self::Host => {
                            let lookup: unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut c_void =
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
        let function: unsafe extern "C" fn() -> i64 = unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { function() }
    }
    fn pointer(self, handle: *mut c_void, name: &str) -> *mut c_void {
        let function: unsafe extern "C" fn() -> *mut c_void = unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { function() }
    }
}

struct Fixture { dir: PathBuf, prefix: String }
impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let prefix = format!("fl_tls_{}_{stamp}", std::process::id());
        let dir = std::env::temp_dir().join(&prefix);
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir, prefix }
    }
    fn name(&self, symbol: &str) -> String { symbol.replace("tls_value", &format!("{}_value", self.prefix)).replace("tls_event", &format!("{}_event", self.prefix)) }
    fn compile(&self, name: &str, source: &str, dependencies: &[&Path], flags: &[&str]) -> PathBuf {
        let source_path = self.dir.join(format!("{name}.c"));
        let library = self.dir.join(format!("{name}.so"));
        std::fs::write(&source_path, self.name(source)).unwrap();
        let output = Command::new("cc").args(["-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=none"])
            .arg(&source_path).args(flags).arg("-Wl,--no-as-needed").args(dependencies)
            .arg("-o").arg(&library).output().unwrap();
        assert!(output.status.success(), "cc failed: {}", String::from_utf8_lossy(&output.stderr));
        library
    }
    fn relocations(&self, path: &Path) -> String {
        let output = Command::new("readelf").args(["-Wr"]).arg(path).output().unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    }
}

fn child_case(name: &str) -> bool {
    if std::env::var("FL_TLS_CHILD").as_deref() == Ok(name) { return true; }
    let mut child = Command::new(std::env::current_exe().unwrap()).args(["--exact", name, "--nocapture"])
        .env("FL_TLS_CHILD", name).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "TLS child {name} failed: {status}");
            return false;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap(); let _ = child.wait();
            panic!("TLS operation deadlocked in {name}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn native_tls_data_bss_alignment_and_dlsym_match_host() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let path = f.compile("data", r#"
            __thread long tls_value=7;
            __thread unsigned char zeroes[65536] __attribute__((aligned(4096)));
            long value(void){return tls_value;}
            void *address(void){return &tls_value;}
            void *aligned_address(void){return zeroes;}
            long zero_tail(void){return zeroes[65535];}
        "#, &[], &[]);
        let relocations=f.relocations(&path);
        assert!(relocations.contains("R_X86_64_DTPMOD64"));
        assert!(relocations.contains("R_X86_64_DTPOFF64"));
        let handle=loader.open(&path,libc::RTLD_NOW); assert!(!handle.is_null(), "TLS fixture was rejected by native loader");
        assert_eq!(loader.value(handle,"value"),7);
        assert_eq!(loader.value(handle,"zero_tail"),0);
        assert_eq!(loader.pointer(handle,"aligned_address") as usize % 4096,0);
        let variable=loader.symbol(handle,&f.name("tls_value"));
        assert_eq!(variable,loader.pointer(handle,"address"));
        unsafe{*variable.cast::<i64>()=31;}
        assert_eq!(loader.value(handle,"value"),31);
        loader.close(handle);
    }
}

#[test]
fn native_tls_existing_and_new_threads_are_isolated() {
    if !child_case("native_tls_existing_and_new_threads_are_isolated") { return; }
    for loader in [Loader::Host, Loader::Native] {
        let f=Fixture::new();
        let path=f.compile("threads",r#"
            __thread long tls_value=5;
            __attribute__((constructor)) static void init(void){tls_value=77;}
            long value(void){return tls_value;} void *address(void){return &tls_value;}
        "#,&[],&[]);
        let barrier=Arc::new(Barrier::new(7)); let shared=Arc::new(AtomicUsize::new(0));
        let mut workers=Vec::new();
        for worker in 0..6 {
            let barrier=barrier.clone(); let shared=shared.clone(); let name=f.name("tls_value");
            workers.push(std::thread::spawn(move||{
                barrier.wait(); // These threads exist before the DSO is loaded.
                barrier.wait();
                let handle=shared.load(Ordering::Acquire) as *mut c_void;
                assert_eq!(loader.value(handle,"value"),5);
                let variable=loader.symbol(handle,&name);
                assert_eq!(variable,loader.pointer(handle,"address"));
                unsafe{*variable.cast::<i64>()=100+worker;}
                barrier.wait();
                assert_eq!(loader.value(handle,"value"),100+worker);
                variable as usize
            }));
        }
        barrier.wait();
        let handle=loader.open(&path,libc::RTLD_NOW); assert!(!handle.is_null());
        assert_eq!(loader.value(handle,"value"),77);
        shared.store(handle as usize,Ordering::Release); barrier.wait(); barrier.wait();
        let mut addresses=workers.into_iter().map(|worker|worker.join().unwrap()).collect::<Vec<_>>();
        addresses.push(loader.pointer(handle,"address") as usize);
        addresses.sort_unstable(); addresses.dedup(); assert_eq!(addresses.len(),7);
        assert_eq!(loader.value(handle,"value"),77);
        let address=handle as usize;
        std::thread::spawn(move||{assert_eq!(loader.value(address as *mut c_void,"value"),5);}).join().unwrap();
        loader.close(handle);
    }
}

#[test]
fn native_tls_local_dynamic_executes() {
    let _serial=SERIAL.lock().unwrap_or_else(|e|e.into_inner());
    for loader in [Loader::Host,Loader::Native] {
        let f=Fixture::new();
        let path=f.compile("local", "static __thread long value=19; static __thread long zero; long next(void){return ++value + zero++;}", &[], &["-O2","-ftls-model=local-dynamic"]);
        assert!(f.relocations(&path).contains("R_X86_64_DTPMOD64"));
        let handle=loader.open(&path,libc::RTLD_NOW); assert!(!handle.is_null());
        assert_eq!(loader.value(handle,"next"),20); assert_eq!(loader.value(handle,"next"),22);
        let address=handle as usize;
        std::thread::spawn(move||{assert_eq!(loader.value(address as *mut c_void,"next"),20);}).join().unwrap();
        loader.close(handle);
    }
}

#[test]
fn native_tls_template_uses_relocated_data() {
    let _serial=SERIAL.lock().unwrap_or_else(|e|e.into_inner());
    for loader in [Loader::Host,Loader::Native] {
        let f=Fixture::new();
        let path=f.compile("template",r#"
            long data[3]={40,41,42}; __thread long *pointer=&data[2];
            long read_value(void){return *pointer;} void *address(void){return pointer;}
        "#,&[],&[]);
        assert!(f.relocations(&path).contains("R_X86_64_64"));
        let handle=loader.open(&path,libc::RTLD_NOW); assert!(!handle.is_null());
        assert_eq!(loader.value(handle,"read_value"),42);
        let data=loader.symbol(handle,"data");
        assert_eq!(loader.pointer(handle,"address") as usize,data as usize+16);
        let address=handle as usize;
        std::thread::spawn(move||{assert_eq!(loader.value(address as *mut c_void,"read_value"),42);}).join().unwrap();
        loader.close(handle);
    }
}

#[test]
fn native_tls_relocation_only_provider_survives_close() {
    let _serial=SERIAL.lock().unwrap_or_else(|e|e.into_inner());
    for loader in [Loader::Host,Loader::Native] {
        let f=Fixture::new();
        let provider=f.compile("provider","__thread long tls_value=10; long value(void){return tls_value;}",&[],&[]);
        let consumer=f.compile("consumer","extern __thread long tls_value; long next(void){return ++tls_value;}",&[],&[]);
        let first=loader.open(&provider,libc::RTLD_NOW|libc::RTLD_GLOBAL); assert!(!first.is_null());
        let second=loader.open(&consumer,libc::RTLD_NOW); assert!(!second.is_null());
        loader.close(first);
        assert_eq!(loader.value(second,"next"),11);
        let address=second as usize;
        std::thread::spawn(move||{assert_eq!(loader.value(address as *mut c_void,"next"),11);}).join().unwrap();
        assert_eq!(loader.value(second,"next"),12);
        let retained=loader.open(&provider,libc::RTLD_NOW|libc::RTLD_NOLOAD); assert_eq!(retained,first);
        assert_eq!(loader.value(retained,"value"),12);
        loader.close(retained); loader.close(second);
        let gone=loader.open(&provider,libc::RTLD_NOW|libc::RTLD_NOLOAD); assert!(gone.is_null());
    }
}

#[test]
fn native_tls_dependency_versions_and_constructor_access() {
    let _serial=SERIAL.lock().unwrap_or_else(|e|e.into_inner());
    for loader in [Loader::Host,Loader::Native] {
        let f=Fixture::new();
        let version=f.dir.join("tls.map");
        std::fs::write(&version,f.name("FL_TLS_1 { global: tls_value; }; ")).unwrap();
        let flag=format!("-Wl,--version-script={}",version.display());
        let provider=f.compile("provider","__thread long tls_value=10;",&[],&[&flag]);
        let consumer=f.compile("consumer",r#"
            extern __thread long tls_value;
            __attribute__((constructor)) static void init(void){tls_value+=7;}
            long value(void){return tls_value;} void *address(void){return &tls_value;}
        "#,&[&provider],&[]);
        let handle=loader.open(&consumer,libc::RTLD_NOW); assert!(!handle.is_null());
        assert_eq!(loader.value(handle,"value"),17);
        let variable=loader.symbol(handle,&f.name("tls_value"));
        assert_eq!(variable,loader.pointer(handle,"address"));
        assert_eq!(variable,loader.lookup(handle,&f.name("tls_value"),Some("FL_TLS_1")));
        assert!(loader.lookup(handle,&f.name("tls_value"),Some("FL_TLS_MISSING")).is_null());
        loader.close(handle);
    }
}

#[test]
fn native_tls_reopen_reload_and_nodelete_keep_correct_generations() {
    let _serial=SERIAL.lock().unwrap_or_else(|e|e.into_inner());
    for loader in [Loader::Host,Loader::Native] {
        let f=Fixture::new();
        let path=f.compile("generations","__thread long tls_value=3; long next(void){return ++tls_value;}",&[],&[]);
        for _ in 0..16 {
            let first=loader.open(&path,libc::RTLD_NOW); assert!(!first.is_null());
            assert_eq!(loader.value(first,"next"),4);
            let second=loader.open(&path,libc::RTLD_NOW|libc::RTLD_NOLOAD); assert_eq!(first,second);
            loader.close(first); assert_eq!(loader.value(second,"next"),5); loader.close(second);
        }
        let handle=loader.open(&path,libc::RTLD_NOW|libc::RTLD_NODELETE); assert!(!handle.is_null());
        assert_eq!(loader.value(handle,"next"),4); loader.close(handle);
        let retained=loader.open(&path,libc::RTLD_NOW|libc::RTLD_NOLOAD); assert_eq!(retained,handle);
        assert_eq!(loader.value(retained,"next"),5); loader.close(retained);
    }
}

fn u16_at(bytes:&[u8],offset:usize)->usize{u16::from_le_bytes(bytes[offset..offset+2].try_into().unwrap()) as usize}
fn u32_at(bytes:&[u8],offset:usize)->u32{u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap())}
fn u64_at(bytes:&[u8],offset:usize)->u64{u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap())}
fn put64(bytes:&mut[u8],offset:usize,value:u64){bytes[offset..offset+8].copy_from_slice(&value.to_le_bytes());}

#[test]
fn native_tls_malformed_metadata_and_relocations_rollback() {
    let _serial=SERIAL.lock().unwrap_or_else(|e|e.into_inner());
    let f=Fixture::new();
    let sink=f.compile("sink","static long events; void tls_event(void){++events;} long count(void){return events;}",&[],&[]);
    let sink=Loader::Native.open(&sink,libc::RTLD_NOW|libc::RTLD_GLOBAL); assert!(!sink.is_null());
    let valid=f.compile("valid","extern void tls_event(void); __thread long tls_value=4; long value(void){return tls_value;} __attribute__((constructor)) static void init(void){tls_event();}",&[],&[]);
    let original=std::fs::read(&valid).unwrap();
    let phoff=u64_at(&original,32) as usize; let phsize=u16_at(&original,54);
    let tls=(0..u16_at(&original,56)).map(|i|phoff+i*phsize).find(|&i|u32_at(&original,i)==7).unwrap();
    let shoff=u64_at(&original,40) as usize; let shsize=u16_at(&original,58);
    let sections=(0..u16_at(&original,60)).map(|i|shoff+i*shsize).collect::<Vec<_>>();
    let rela=sections.iter().filter(|&&i|u32_at(&original,i+4)==4).find_map(|&i|{
        let start=u64_at(&original,i+24) as usize; let size=u64_at(&original,i+32) as usize;
        (start..start+size).step_by(24).find(|&i|matches!(u64_at(&original,i+8) as u32,16|17))
    }).unwrap();
    for case in 0..5 {
        let mut bytes=original.clone();
        match case {
            0=>put64(&mut bytes,tls+40,0), // filesz > memsz
            1=>put64(&mut bytes,tls+48,3), // invalid alignment
            2=>put64(&mut bytes,tls+8,u64::MAX-16), // template outside file
            3=>put64(&mut bytes,tls+16,0x1000_0000), // template not backed by PT_LOAD
            4=>put64(&mut bytes,rela,u64::MAX-7), // invalid GOT target
            _=>unreachable!(),
        }
        let path=f.dir.join(format!("bad-{case}.so")); std::fs::write(&path,bytes).unwrap();
        assert!(Loader::Native.open(&path,libc::RTLD_NOW).is_null(),"malformed TLS case {case} loaded");
        assert!(!unsafe{dlerror()}.is_null());
        assert_eq!(Loader::Native.value(sink,"count"),0,"initializer ran before validation");
    }
    let handle=Loader::Native.open(&valid,libc::RTLD_NOW); assert!(!handle.is_null());
    assert_eq!(Loader::Native.value(handle,"value"),4); assert_eq!(Loader::Native.value(sink,"count"),1);
    Loader::Native.close(handle); Loader::Native.close(sink);
}

#[test]
fn native_tls_unsupported_models_are_not_silently_loaded() {
    let _serial=SERIAL.lock().unwrap_or_else(|e|e.into_inner());
    let f=Fixture::new();
    // Initial-exec still requires integration with the host static TLS layout.
    // GNU2 descriptors now have execution and malformed-pair rollback coverage
    // in dlfcn_native_tlsdesc_test; blanket rejection is no longer the contract.
    for (index,flag,relocation) in [(0,"-ftls-model=initial-exec","R_X86_64_TPOFF64")] {
        let path=f.compile(&format!("unsupported-{index}"),"__thread long tls_value=7; long value(void){return tls_value;}",&[],&[flag]);
        assert!(f.relocations(&path).contains(relocation));
        assert!(Loader::Native.open(&path,libc::RTLD_NOW).is_null());
        assert!(!unsafe{dlerror()}.is_null());
        let host=Loader::Host.open(&path,libc::RTLD_NOW); assert!(!host.is_null());
        assert_eq!(Loader::Host.value(host,"value"),7); Loader::Host.close(host);
    }
}

#[test]
fn native_tls_unresolved_import_does_not_initialize_dependencies() {
    let _serial=SERIAL.lock().unwrap_or_else(|e|e.into_inner());
    for loader in [Loader::Host,Loader::Native] {
        let f=Fixture::new();
        let sink=f.compile("sink","static long count; void tls_event(void){++count;} long events(void){return count;}",&[],&[]);
        let sink=loader.open(&sink,libc::RTLD_NOW|libc::RTLD_GLOBAL); assert!(!sink.is_null());
        let dependency=f.compile("dependency","extern void tls_event(void); __attribute__((constructor)) static void init(void){tls_event();}",&[],&[]);
        let root=f.compile("missing","extern __thread long tls_value; long value(void){return tls_value;}",&[&dependency],&[]);
        assert!(loader.open(&root,libc::RTLD_NOW).is_null());
        assert_eq!(loader.value(sink,"events"),0);
        let handle=loader.open(&dependency,libc::RTLD_NOW); assert!(!handle.is_null());
        assert_eq!(loader.value(sink,"events"),1);
        loader.close(handle); loader.close(sink);
    }
}
