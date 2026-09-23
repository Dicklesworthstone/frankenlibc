//! Execute GNU2 TLS descriptors in compiled DSOs, never host-fallback handles.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{
    dlclose, dlerror, dlopen, dlsym, dlvsym, native_dso_handle_for_tests,
};
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

#[derive(Clone, Copy)]
enum Loader { Host, Native }

impl Loader {
    fn try_open(self, path: &Path, flags: c_int) -> *mut c_void {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: live C path; the caller owns every successful open reference.
        let handle = unsafe {
            match self {
                Self::Native => dlopen(path.as_ptr(), flags),
                Self::Host => {
                    let function: unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void =
                        dlsym_oracle::host_fn(c"dlopen", dlopen as *const ());
                    function(path.as_ptr(), flags)
                }
            }
        };
        if matches!(self, Self::Native) && !handle.is_null() {
            assert!(native_dso_handle_for_tests(handle), "host fallback is not TLSDESC execution");
        }
        handle
    }
    fn open(self, path: &Path, flags: c_int) -> *mut c_void {
        let handle = self.try_open(path, flags);
        assert!(!handle.is_null(), "TLSDESC fixture must load natively: {path:?}");
        handle
    }
    fn close(self, handle: *mut c_void) {
        // SAFETY: caller retains its handle until all fixture calls finish.
        let result = unsafe {
            match self {
                Self::Native => dlclose(handle),
                Self::Host => {
                    let function: unsafe extern "C" fn(*mut c_void) -> c_int =
                        dlsym_oracle::host_fn(c"dlclose", dlclose as *const ());
                    function(handle)
                }
            }
        };
        assert_eq!(result, 0);
    }
    fn symbol(self, handle: *mut c_void, name: &str) -> *mut c_void {
        let name = CString::new(name).unwrap();
        // SAFETY: the handle is live and name is NUL-terminated.
        let address = unsafe {
            match self {
                Self::Native => dlsym(handle, name.as_ptr()),
                Self::Host => {
                    let function: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void =
                        dlsym_oracle::host_fn(c"dlsym", dlsym as *const ());
                    function(handle, name.as_ptr())
                }
            }
        };
        assert!(!address.is_null(), "missing fixture symbol {name:?}");
        address
    }
    fn value(self, handle: *mut c_void, name: &str) -> i64 {
        // SAFETY: these compiled fixture entry points have signature long(void).
        let function: unsafe extern "C" fn() -> i64 = unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { function() }
    }
    fn pointer(self, handle: *mut c_void, name: &str) -> *mut c_void {
        // SAFETY: these compiled fixture entry points have signature void *(void).
        let function: unsafe extern "C" fn() -> *mut c_void = unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { function() }
    }
}

struct Fixture { dir: PathBuf, prefix: String }
impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let prefix = format!("fl_tlsdesc_{}_{stamp}", std::process::id());
        let dir = std::env::temp_dir().join(&prefix);
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir, prefix }
    }
    fn names(&self, source: &str) -> String {
        source.replace("td_value", &format!("{}_value", self.prefix))
    }
    fn compile(&self, name: &str, source: &str, inputs: &[&Path], flags: &[&str]) -> PathBuf {
        let file = self.dir.join(format!("{name}.c"));
        let library = self.dir.join(format!("{name}.so"));
        std::fs::write(&file, self.names(source)).unwrap();
        let output = Command::new("cc")
            .args(["-shared", "-fPIC", "-nostdlib", "-O2", "-mtls-dialect=gnu2",
                "-Wl,--build-id=none", "-Wl,-z,now", "-Wl,-z,relro", "-Wl,--no-as-needed"])
            .arg(&file).args(inputs).args(flags).arg("-o").arg(&library)
            .output().expect("C compiler required; missing tools are not skips");
        assert!(output.status.success(), "C fixture failed: {}", String::from_utf8_lossy(&output.stderr));
        library
    }
    fn require_desc(&self, path: &Path) {
        let output = Command::new("readelf").arg("-Wr").arg(path).output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("R_X86_64_TLSDESC"), "fixture lacks TLSDESC relocation");
    }
}

fn child_case(name: &str) -> bool {
    if std::env::var("FL_TLSDESC_CHILD").as_deref() == Ok(name) { return true; }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"]).env("FL_TLSDESC_CHILD", name).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "TLSDESC child {name} failed: {status}");
            return false;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap(); let _ = child.wait();
            panic!("TLSDESC operation deadlocked in {name}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn native_tlsdesc_data_bss_alignment_and_dlsym_match_host() {
    if !child_case("native_tlsdesc_data_bss_alignment_and_dlsym_match_host") { return; }
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let path = f.compile("data", r#"
            __thread long td_value=7;
            __thread unsigned char zeros[65536] __attribute__((aligned(4096)));
            long value(void){return td_value;} void *address(void){return &td_value;}
            long tail(void){return zeros[65535];} void *aligned_address(void){return zeros;}
        "#, &[], &[]);
        f.require_desc(&path);
        let h = loader.open(&path, libc::RTLD_NOW);
        assert_eq!(loader.value(h, "value"), 7);
        assert_eq!(loader.value(h, "tail"), 0);
        assert_eq!(loader.pointer(h, "aligned_address") as usize % 4096, 0);
        let variable = loader.symbol(h, &f.names("td_value"));
        assert_eq!(variable, loader.pointer(h, "address"));
        // SAFETY: a live long TLS object on this thread, retained by h.
        unsafe { *variable.cast::<i64>() = 41; }
        assert_eq!(loader.value(h, "value"), 41);
        loader.close(h);
    }
}

#[test]
fn native_tlsdesc_existing_and_new_threads_are_isolated() {
    if !child_case("native_tlsdesc_existing_and_new_threads_are_isolated") { return; }
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let path = f.compile("threads", r#"
            __thread long td_value=5;
            __attribute__((constructor)) static void init(void){td_value=77;}
            long value(void){return td_value;} void *address(void){return &td_value;}
        "#, &[], &[]);
        f.require_desc(&path);
        let barrier = Arc::new(Barrier::new(7));
        let shared = Arc::new(AtomicUsize::new(0));
        let workers = (0..6).map(|index| {
            let barrier = barrier.clone(); let shared = shared.clone();
            std::thread::spawn(move || {
                barrier.wait(); barrier.wait();
                let h = shared.load(Ordering::Acquire) as *mut c_void;
                assert_eq!(loader.value(h, "value"), 5);
                let variable = loader.pointer(h, "address");
                // SAFETY: this worker exclusively mutates its own TLS object.
                unsafe { *variable.cast::<i64>() = 100 + index; }
                barrier.wait();
                assert_eq!(loader.value(h, "value"), 100 + index);
                variable as usize
            })
        }).collect::<Vec<_>>();
        barrier.wait(); // Workers already exist when the module is loaded.
        let h = loader.open(&path, libc::RTLD_NOW);
        assert_eq!(loader.value(h, "value"), 77);
        shared.store(h as usize, Ordering::Release);
        barrier.wait(); barrier.wait();
        let mut addresses = workers.into_iter().map(|worker| worker.join().unwrap()).collect::<Vec<_>>();
        addresses.push(loader.pointer(h, "address") as usize);
        addresses.sort_unstable(); addresses.dedup(); assert_eq!(addresses.len(), 7);
        let retained = h as usize;
        std::thread::spawn(move || {
            assert_eq!(loader.value(retained as *mut c_void, "value"), 5);
        }).join().unwrap();
        assert_eq!(loader.value(h, "value"), 77);
        loader.close(h);
    }
}

#[test]
fn native_tlsdesc_and_gnu1_access_share_one_block() {
    if !child_case("native_tlsdesc_and_gnu1_access_share_one_block") { return; }
    for loader in [Loader::Host, Loader::Native] {
        for dialect in ["gnu", "gnu2"] {
            let f = Fixture::new();
            let flag = format!("-mtls-dialect={dialect}");
            let provider = f.compile("provider", "__thread long td_value=10; long value(void){return td_value;}", &[], &[&flag]);
            let other = if dialect == "gnu" { "-mtls-dialect=gnu2" } else { "-mtls-dialect=gnu" };
            let consumer = f.compile("consumer", "extern __thread long td_value; long next(void){return ++td_value;}", &[&provider], &[other]);
            f.require_desc(if dialect == "gnu" { &consumer } else { &provider });
            let h = loader.open(&consumer, libc::RTLD_NOW);
            assert_eq!(loader.value(h, "next"), 11);
            assert_eq!(loader.value(h, "value"), 11);
            // SAFETY: dlsym returns the same thread-local long used by both dialects.
            unsafe { *loader.symbol(h, &f.names("td_value")).cast::<i64>() = 40; }
            assert_eq!(loader.value(h, "next"), 41);
            assert_eq!(loader.value(h, "value"), 41);
            loader.close(h);
        }
    }
}

#[test]
fn native_tlsdesc_binding_and_provider_lifetimes_match_host() {
    if !child_case("native_tlsdesc_binding_and_provider_lifetimes_match_host") { return; }
    for loader in [Loader::Host, Loader::Native] {
        for case in 0..4 {
            let f = Fixture::new();
            let provider = f.compile("provider", "__thread long td_value=40;", &[], &[]);
            let source = if case == 2 {
                "__thread long td_value __attribute__((visibility(\"protected\")))=3; long next(void){return ++td_value;}"
            } else { "__thread long td_value=3; long next(void){return ++td_value;}" };
            let flags = if case == 3 { vec!["-Wl,-Bsymbolic"] } else { vec![] };
            let consumer = f.compile("consumer", source, &[], &flags);
            f.require_desc(&consumer);
            let first = loader.open(&provider, libc::RTLD_NOW | libc::RTLD_GLOBAL);
            let mode = libc::RTLD_NOW | if case == 1 { libc::RTLD_DEEPBIND } else { 0 };
            let second = loader.open(&consumer, mode);
            loader.close(first);
            assert_eq!(loader.value(second, "next"), if case == 0 { 41 } else { 4 });
            if case == 0 {
                let retained = loader.open(&provider, libc::RTLD_NOW | libc::RTLD_NOLOAD);
                loader.close(retained);
                let address = second as usize;
                std::thread::spawn(move || {
                    assert_eq!(loader.value(address as *mut c_void, "next"), 41);
                }).join().unwrap();
            }
            loader.close(second);
            assert!(loader.try_open(&provider, libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
        }
    }
}

#[test]
fn native_tlsdesc_versioned_imports_work_in_constructors() {
    if !child_case("native_tlsdesc_versioned_imports_work_in_constructors") { return; }
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let map = f.dir.join("versions.map");
        std::fs::write(&map, f.names("FL_DESC_1 { global: td_value; }; ")).unwrap();
        let flag = format!("-Wl,--version-script={}", map.display());
        let provider = f.compile("provider", "__thread long td_value=10;", &[], &[&flag]);
        let consumer = f.compile("consumer", r#"
            extern __thread long td_value;
            __attribute__((constructor)) static void init(void){td_value+=7;}
            long value(void){return td_value;} void *address(void){return &td_value;}
        "#, &[&provider], &[]);
        f.require_desc(&consumer);
        let h = loader.open(&consumer, libc::RTLD_NOW);
        assert_eq!(loader.value(h, "value"), 17);
        let name = CString::new(f.names("td_value")).unwrap();
        // SAFETY: retained handle, live symbol/version strings, matching host/native API.
        let versioned = unsafe {
            match loader {
                Loader::Native => dlvsym(h, name.as_ptr(), c"FL_DESC_1".as_ptr()),
                Loader::Host => {
                    let lookup: unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut c_void =
                        dlsym_oracle::host_fn(c"dlvsym", dlvsym as *const ());
                    lookup(h, name.as_ptr(), c"FL_DESC_1".as_ptr())
                }
            }
        };
        assert_eq!(versioned, loader.pointer(h, "address"));
        loader.close(h);
    }
}

#[test]
fn native_tlsdesc_ifunc_tls_writes_survive_until_constructor() {
    if !child_case("native_tlsdesc_ifunc_tls_writes_survive_until_constructor") { return; }
    let f = Fixture::new();
    let path = f.compile("ifunc", r#"
        __thread long td_value=10;
        static long implementation(void){return td_value;}
        static void *resolver(void){td_value=30;return implementation;}
        long choose(void) __attribute__((ifunc("resolver")));
        long (*selected)(void)=choose;
        __attribute__((constructor)) static void init(void){td_value+=12;}
        long run(void){return selected();}
    "#, &[], &[]);
    f.require_desc(&path);
    let h = Loader::Native.open(&path, libc::RTLD_NOW);
    assert_eq!(Loader::Native.value(h, "run"), 42);
    let retained = h as usize;
    std::thread::spawn(move || {
        assert_eq!(Loader::Native.value(retained as *mut c_void, "run"), 10);
    }).join().unwrap();
    Loader::Native.close(h);
}

#[test]
fn native_tlsdesc_undefined_weak_is_null_but_type_mismatch_is_rejected() {
    if !child_case("native_tlsdesc_undefined_weak_is_null_but_type_mismatch_is_rejected") { return; }
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let weak = f.compile("weak", "extern __thread long td_value __attribute__((weak)); void *address(void){return &td_value;}", &[], &[]);
        f.require_desc(&weak);
        let h = loader.open(&weak, libc::RTLD_NOW);
        assert!(loader.pointer(h, "address").is_null());
        loader.close(h);
        if matches!(loader, Loader::Native) {
            let wrong = f.compile("wrong", "long td_value=7;", &[], &[]);
            let first = loader.open(&wrong, libc::RTLD_NOW | libc::RTLD_GLOBAL);
            assert!(loader.try_open(&weak, libc::RTLD_NOW).is_null());
            assert!(!unsafe { dlerror() }.is_null());
            loader.close(first);
        }
    }
}

#[test]
fn native_tlsdesc_reload_and_nodelete_keep_correct_generations() {
    if !child_case("native_tlsdesc_reload_and_nodelete_keep_correct_generations") { return; }
    for loader in [Loader::Host, Loader::Native] {
        let f = Fixture::new();
        let path = f.compile("generations", "__thread long td_value=3; long next(void){return ++td_value;}", &[], &[]);
        f.require_desc(&path);
        for _ in 0..16 {
            let first = loader.open(&path, libc::RTLD_NOW);
            assert_eq!(loader.value(first, "next"), 4);
            let second = loader.open(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD);
            assert_eq!(first, second); loader.close(first);
            assert_eq!(loader.value(second, "next"), 5); loader.close(second);
        }
        let h = loader.open(&path, libc::RTLD_NOW | libc::RTLD_NODELETE);
        assert_eq!(loader.value(h, "next"), 4); loader.close(h);
        let retained = loader.open(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD);
        assert_eq!(h, retained); assert_eq!(loader.value(retained, "next"), 5);
        loader.close(retained);
    }
}

fn u16_at(bytes: &[u8], at: usize) -> usize { u16::from_le_bytes(bytes[at..at+2].try_into().unwrap()) as usize }
fn u32_at(bytes: &[u8], at: usize) -> u32 { u32::from_le_bytes(bytes[at..at+4].try_into().unwrap()) }
fn u64_at(bytes: &[u8], at: usize) -> u64 { u64::from_le_bytes(bytes[at..at+8].try_into().unwrap()) }
fn put64(bytes: &mut [u8], at: usize, value: u64) { bytes[at..at+8].copy_from_slice(&value.to_le_bytes()); }

#[test]
fn native_tlsdesc_bad_pairs_and_imports_rollback_before_callbacks() {
    if !child_case("native_tlsdesc_bad_pairs_and_imports_rollback_before_callbacks") { return; }
    let f = Fixture::new();
    let sink = f.compile("sink", "static long n; void record(void){++n;} long count(void){return n;}", &[], &[]);
    let sink = Loader::Native.open(&sink, libc::RTLD_NOW | libc::RTLD_GLOBAL);
    let valid = f.compile("valid", "extern void record(void); __thread long td_value=7; long value(void){return td_value;} __attribute__((constructor)) static void init(void){record();}", &[], &[]);
    f.require_desc(&valid);
    let original = std::fs::read(&valid).unwrap();
    let phoff = u64_at(&original, 32) as usize; let phsize = u16_at(&original, 54);
    let loads = (0..u16_at(&original, 56)).map(|i| phoff+i*phsize)
        .filter(|&i| u32_at(&original, i) == 1).collect::<Vec<_>>();
    let load = *loads.last().unwrap();
    let end = u64_at(&original, load+16)+u64_at(&original, load+40);
    let shoff = u64_at(&original, 40) as usize; let shsize = u16_at(&original, 58);
    let rela = (0..u16_at(&original, 60)).map(|i| shoff+i*shsize)
        .filter(|&i| u32_at(&original, i+4) == 4).find_map(|i| {
            let start = u64_at(&original, i+24) as usize;
            let count = u64_at(&original, i+32) as usize;
            (start..start+count).step_by(24).find(|&i| u64_at(&original, i+8) as u32 == 36)
        }).unwrap();
    for case in 0..4 {
        let mut bytes = original.clone();
        match case {
            0 => put64(&mut bytes, rela, end-8), // Only the first descriptor word fits PT_LOAD.
            1 => put64(&mut bytes, rela, u64::MAX-7),
            2 => put64(&mut bytes, rela+16, i64::MAX as u64),
            3 => put64(&mut bytes, rela+8, (u32::MAX as u64) << 32 | 36),
            _ => unreachable!(),
        }
        let path = f.dir.join(format!("bad-{case}.so")); std::fs::write(&path, bytes).unwrap();
        assert!(Loader::Native.try_open(&path, libc::RTLD_NOW).is_null(), "bad TLSDESC case {case} loaded");
        let error = unsafe { dlerror() };
        assert!(!error.is_null());
        // SAFETY: dlerror's live thread-local C string; do not invoke it again first.
        assert!(!unsafe { CStr::from_ptr(error) }.to_bytes().is_empty());
        assert!(Loader::Native.try_open(&path, libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
        assert_eq!(Loader::Native.value(sink, "count"), 0);
    }
    let dependency = f.compile("dependency", "extern void record(void); __attribute__((constructor)) static void init(void){record();}", &[], &[]);
    let missing = f.compile("missing", "extern __thread long td_value_missing; long value(void){return td_value_missing;}", &[&dependency], &[]);
    f.require_desc(&missing);
    assert!(Loader::Native.try_open(&missing, libc::RTLD_NOW).is_null());
    assert!(Loader::Native.try_open(&dependency, libc::RTLD_NOW | libc::RTLD_NOLOAD).is_null());
    assert_eq!(Loader::Native.value(sink, "count"), 0);
    let h = Loader::Native.open(&valid, libc::RTLD_NOW);
    assert_eq!(Loader::Native.value(h, "value"), 7);
    assert_eq!(Loader::Native.value(sink, "count"), 1);
    Loader::Native.close(h); Loader::Native.close(sink);
}

#[test]
fn native_tlsdesc_cold_and_warm_calls_preserve_registers_and_relro() {
    if !child_case("native_tlsdesc_cold_and_warm_calls_preserve_registers_and_relro") { return; }
    let f = Fixture::new();
    let assembly = f.dir.join("probe.S");
    std::fs::write(&assembly, include_str!("fixtures/tlsdesc_state_probe.S")).unwrap();
    let path = f.compile("registers", r#"
        __thread long td_value=7;
        __asm__(".text\n.globl descriptor\n.type descriptor,@function\ndescriptor:\n"
                "leaq td_value@TLSDESC(%rip), %rax\nret\n.size descriptor,.-descriptor\n");
    "#, &[&assembly], &[]);
    f.require_desc(&path);
    let h = Loader::Native.open(&path, libc::RTLD_NOW);
    let descriptor = Loader::Native.pointer(h, "descriptor") as usize;
    let probe = Loader::Native.symbol(h, "probe_state") as usize;
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let permissions = maps.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let (lo, hi) = fields.next()?.split_once('-')?;
        let low = usize::from_str_radix(lo, 16).ok()?; let high = usize::from_str_radix(hi, 16).ok()?;
        let permissions = fields.next()?;
        (low <= descriptor && descriptor+16 <= high).then_some(permissions)
    }).expect("descriptor is mapped");
    assert!(!permissions.contains('w'), "descriptor must be sealed by RELRO");
    let mut widths = vec![128];
    if std::is_x86_feature_detected!("avx") { widths.push(256); }
    if std::is_x86_feature_detected!("avx512f") { widths.push(512); }
    for bits in widths {
        // No dlsym(TLS) or C TLS read precedes the probe on this new thread.
        // The null expected address asks the probe to validate value 7, so the
        // first register-preserving call must allocate and initialize the block.
        std::thread::spawn(move || {
            let function: unsafe extern "C" fn(usize, u32, usize) -> c_int = unsafe { std::mem::transmute(probe) };
            for _ in 0..8 {
                assert_eq!(unsafe { function(descriptor, bits, 0) }, 0, "{bits}-bit TLSDESC preservation failed");
            }
        }).join().unwrap();
    }
    Loader::Native.close(h);
}
