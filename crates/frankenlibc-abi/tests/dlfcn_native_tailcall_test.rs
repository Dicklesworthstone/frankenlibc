//! Compiler tail calls must not escape the native allocation/lookup namespace.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use frankenlibc_abi::{dlfcn_abi as dl, malloc_abi};
use frankenlibc_core::elf::ElfLoader;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type Query = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type Versioned = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type Lookup = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type VLookup = unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut c_void;

const SOURCE: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
int tail_local(void) { return VALUE; }
__thread int tail_tls = VALUE;
int old_value(void) { return VALUE+1; }
int new_value(void) { return VALUE+2; }
__asm__(".symver old_value,tail_version@TAIL_1");
__asm__(".symver new_value,tail_version@@TAIL_2");
__asm__(".globl tail_zero\n.set tail_zero,0");
static void *choose_null(void) { return 0; }
int tail_null(void) __attribute__((ifunc("choose_null")));
void *tail_default(const char *n) { return dlsym(RTLD_DEFAULT,n); }
void *tail_next(const char *n) { return dlsym(RTLD_NEXT,n); }
void *tail_versioned(const char *n,const char *v) { return dlvsym(RTLD_DEFAULT,n,v); }
void *direct_lookup(void) { return (void *)dlsym; }
void *direct_versioned(void) { return (void *)dlvsym; }
void *borrow_lookup(void *(*lookup)(void *,const char *),const char *name) {
    void *p=lookup(RTLD_DEFAULT,name);
    __asm__ __volatile__("" : "+r"(p));
    return p;
}
int allocated_protocol(void) {
    void *(*allocate)(size_t,size_t)=dlsym(RTLD_DEFAULT,"calloc");
    void (*release)(void *)=dlsym(RTLD_DEFAULT,"free");
    unsigned char *p=allocate(64,1); if(!p) return 1;
    int error=0; for(unsigned i=0;i<64;++i) if(p[i]) error=2;
    release(p); return error;
}
"#;

struct Fixture {
    dir: PathBuf,
    got: bool,
}
impl Fixture {
    fn new(got: bool) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc-tailcall-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("versions.map"), "TAIL_1 {}; TAIL_2 {} TAIL_1;\n").unwrap();
        let f = Self { dir, got };
        f.build("child", 33, false);
        f.build("left", 11, true);
        f.build("right", 22, true);
        f
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("lib{name}.so"))
    }
    fn build(&self, name: &str, value: i32, needed: bool) {
        let input = self.dir.join(format!("{name}.c"));
        std::fs::write(&input, SOURCE.replace("VALUE", &value.to_string())).unwrap();
        let mut cc = Command::new("cc");
        cc.args([
            "-shared",
            "-fPIC",
            "-nostdlib",
            "-O2",
            "-fno-builtin",
            "-U_FORTIFY_SOURCE",
            "-D_FORTIFY_SOURCE=0",
        ])
        .arg(format!(
            "-Wl,--version-script={}",
            self.dir.join("versions.map").display()
        ));
        if self.got {
            cc.arg("-fno-plt");
        }
        if needed {
            cc.arg(format!("-L{}", self.dir.display())).args([
                "-Wl,--no-as-needed",
                "-lchild",
                "-Wl,-rpath,$ORIGIN",
            ]);
        }
        let output = cc
            .arg(&input)
            .arg("-o")
            .arg(self.path(name))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let object = ElfLoader::new(0)
            .parse(&std::fs::read(self.path(name)).unwrap())
            .unwrap();
        assert_eq!(
            object.needed_libraries,
            if needed {
                vec!["libchild.so".to_owned()]
            } else {
                vec![]
            }
        );
        // Require an actual optimized sibling jump, not a barrier in the fixture
        // that accidentally hides the original return-PC-only failure.
        for symbol in ["tail_default", "tail_next", "tail_versioned"] {
            let output = Command::new("objdump")
                .args(["-d", "--no-show-raw-insn"])
                .arg(format!("--disassemble={symbol}"))
                .arg(self.path(name))
                .output()
                .unwrap();
            assert!(output.status.success());
            let assembly = String::from_utf8(output.stdout).unwrap();
            assert!(
                assembly.lines().any(|line| line.contains("jmp")),
                "no tail jump: {assembly}"
            );
            assert!(
                !assembly.lines().any(|line| line.contains("\tret")),
                "unexpected wrapper frame: {assembly}"
            );
        }
    }
}

struct Library(*mut c_void);
impl Library {
    fn new(path: &Path) -> Self {
        let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: terminated compiler-created pathname; the handle owns its mappings.
        let handle = unsafe { dl::dlopen(path.as_ptr(), libc::RTLD_NOW) };
        assert!(!handle.is_null());
        assert!(dl::native_dso_handle_for_tests(handle), "host fallback");
        Self(handle)
    }
    fn symbol(&self, name: &CStr) -> *mut c_void {
        // SAFETY: retained live handle and terminated name.
        let p = unsafe { dl::dlsym(self.0, name.as_ptr()) };
        assert!(!p.is_null(), "{name:?}");
        p
    }
    fn query(&self) -> Query {
        // SAFETY: this entry has exactly the compiled C Query signature.
        unsafe { std::mem::transmute(self.symbol(c"tail_default")) }
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: tests join callers and stop using pointers before releasing a handle.
        assert_eq!(unsafe { dl::dlclose(self.0) }, 0);
    }
}

fn value(p: *mut c_void) -> i32 {
    assert!(!p.is_null());
    // SAFETY: all value probes are the compiled zero-argument int functions.
    let f: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(p) };
    unsafe { f() }
}

fn isolated(name: &str, body: fn()) {
    if std::env::var_os("FL_TAILCALL_CHILD").is_some() {
        body();
        return;
    }
    for mode in ["strict", "hardened"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FL_TAILCALL_CHILD", "1")
            .env("FRANKENLIBC_MODE", mode)
            .env_remove("LD_PRELOAD")
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{name}/{mode}: {status}");
                break;
            }
            if start.elapsed() > Duration::from_secs(45) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{name}/{mode}: timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn tail_calls_preserve_local_next_version_tls_and_zero_results() {
    isolated(
        "tail_calls_preserve_local_next_version_tls_and_zero_results",
        || {
            for got in [false, true] {
                let f = Fixture::new(got);
                let left = Library::new(&f.path("left"));
                let right = Library::new(&f.path("right"));
                for (lib, expected) in [(&left, 11), (&right, 22)] {
                    let query = lib.query();
                    // SAFETY: all C entry signatures and symbol names are exact.
                    unsafe {
                        assert_eq!(value(query(c"tail_local".as_ptr())), expected);
                        assert_eq!(
                            query(c"calloc".as_ptr()),
                            malloc_abi::calloc as *const () as *mut c_void
                        );
                        let next: Query = std::mem::transmute(lib.symbol(c"tail_next"));
                        assert_eq!(value(next(c"tail_local".as_ptr())), 33);
                        assert!(next(c"malloc".as_ptr()).is_null());
                        assert!(!dl::dlerror().is_null());
                        let versioned: Versioned =
                            std::mem::transmute(lib.symbol(c"tail_versioned"));
                        assert_eq!(
                            value(versioned(c"tail_version".as_ptr(), c"TAIL_1".as_ptr())),
                            expected + 1
                        );
                        assert_eq!(
                            value(versioned(c"tail_version".as_ptr(), c"TAIL_2".as_ptr())),
                            expected + 2
                        );
                        assert!(versioned(c"calloc".as_ptr(), c"GLIBC_2.34".as_ptr()).is_null());
                        assert!(!dl::dlerror().is_null());
                        for name in [c"tail_zero", c"tail_null"] {
                            assert!(query(name.as_ptr()).is_null());
                            assert!(dl::dlerror().is_null(), "zero is success");
                        }
                        assert!(query(c"missing_tail_symbol".as_ptr()).is_null());
                        assert!(!dl::dlerror().is_null());
                        assert!(dl::dlerror().is_null(), "errors clear on consumption");
                    }
                    let slots = std::thread::scope(|scope| {
                        let one = scope.spawn(|| {
                            // SAFETY: TLS address belongs to this thread; DSO remains pinned.
                            let p = unsafe { query(c"tail_tls".as_ptr()) }.cast::<i32>();
                            assert_eq!(unsafe { *p }, expected);
                            unsafe { *p = 71 };
                            p as usize
                        });
                        let two = scope.spawn(|| {
                            // SAFETY: same thread-local API, independent worker TLS allocation.
                            let p = unsafe { query(c"tail_tls".as_ptr()) }.cast::<i32>();
                            assert_eq!(unsafe { *p }, expected);
                            unsafe { *p = 82 };
                            p as usize
                        });
                        (one.join().unwrap(), two.join().unwrap())
                    });
                    assert_ne!(slots.0, 0);
                    assert_ne!(slots.1, 0);
                    // Slot addresses can be reused after a worker exits; isolation is
                    // verified separately below with concurrent barriers.
                }
            }
        },
    );
}

#[test]
fn bound_helpers_keep_identity_and_real_native_callers_take_precedence() {
    isolated(
        "bound_helpers_keep_identity_and_real_native_callers_take_precedence",
        || {
            let f = Fixture::new(true);
            let left = Library::new(&f.path("left"));
            let right = Library::new(&f.path("right"));
            // SAFETY: exact signatures from SOURCE; both libraries remain open.
            unsafe {
                let direct: unsafe extern "C" fn() -> *mut c_void =
                    std::mem::transmute(left.symbol(c"direct_lookup"));
                let direct_v: unsafe extern "C" fn() -> *mut c_void =
                    std::mem::transmute(left.symbol(c"direct_versioned"));
                let helper = left.query()(c"dlsym".as_ptr());
                assert_eq!(helper, direct());
                let vhelper = left.query()(c"dlvsym".as_ptr());
                assert_eq!(vhelper, direct_v());
                let lookup: Lookup = std::mem::transmute(helper);
                let versioned: VLookup = std::mem::transmute(vhelper);
                assert_eq!(
                    value(lookup(libc::RTLD_DEFAULT, c"tail_local".as_ptr())),
                    11
                );
                assert_eq!(
                    value(versioned(
                        libc::RTLD_DEFAULT,
                        c"tail_version".as_ptr(),
                        c"TAIL_1".as_ptr()
                    )),
                    12
                );
                // Explicit handles are never overridden by the bound origin.
                assert_eq!(value(lookup(right.0, c"tail_local".as_ptr())), 22);
                let borrow: unsafe extern "C" fn(Lookup, *const c_char) -> *mut c_void =
                    std::mem::transmute(right.symbol(c"borrow_lookup"));
                assert_eq!(
                    value(borrow(lookup, c"tail_local".as_ptr())),
                    22,
                    "real native caller wins over fallback origin"
                );
                let run: unsafe extern "C" fn() -> c_int =
                    std::mem::transmute(left.symbol(c"allocated_protocol"));
                assert_eq!(run(), 0);
            }
        },
    );
}

#[test]
fn concurrent_tail_calls_do_not_share_origin_or_tls_state() {
    isolated(
        "concurrent_tail_calls_do_not_share_origin_or_tls_state",
        || {
            let f = Fixture::new(false);
            let left = Library::new(&f.path("left"));
            let right = Library::new(&f.path("right"));
            let barrier = std::sync::Barrier::new(4);
            std::thread::scope(|scope| {
                for index in 0..4 {
                    let query = if index % 2 == 0 {
                        left.query()
                    } else {
                        right.query()
                    };
                    let expected = if index % 2 == 0 { 11 } else { 22 };
                    let barrier = &barrier;
                    scope.spawn(move || {
                        // SAFETY: thread-local pointer is live while this DSO and thread live.
                        let tls = unsafe { query(c"tail_tls".as_ptr()) }.cast::<i32>();
                        assert!(!tls.is_null());
                        assert_eq!(unsafe { *tls }, expected);
                        unsafe { *tls = 100 + index };
                        barrier.wait();
                        for _ in 0..100 {
                            // SAFETY: the owning libraries remain pinned by the parent.
                            assert_eq!(value(unsafe { query(c"tail_local".as_ptr()) }), expected);
                            assert_eq!(unsafe { *tls }, 100 + index);
                        }
                        barrier.wait();
                    });
                }
            });
        },
    );
}

fn protection(address: usize) -> Option<String> {
    std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let (lo, hi) = fields.next()?.split_once('-')?;
            let lo = usize::from_str_radix(lo, 16).ok()?;
            let hi = usize::from_str_radix(hi, 16).ok()?;
            (lo <= address && address < hi).then(|| fields.next().unwrap().to_owned())
        })
}

#[test]
fn lookup_bridge_pages_are_never_writable_and_retire_with_the_object() {
    isolated(
        "lookup_bridge_pages_are_never_writable_and_retire_with_the_object",
        || {
            let f = Fixture::new(false);
            for _ in 0..12 {
                let lib = Library::new(&f.path("left"));
                // SAFETY: the query returns the bound code pointer, never dereferenced as data.
                let pointer = unsafe { lib.query()(c"dlsym".as_ptr()) } as usize;
                assert_ne!(pointer, 0);
                assert_eq!(protection(pointer).as_deref(), Some("r-xp"));
                drop(lib);
                assert!(
                    protection(pointer).is_none(),
                    "lookup mapping leaked after dlclose"
                );
            }
        },
    );
}
