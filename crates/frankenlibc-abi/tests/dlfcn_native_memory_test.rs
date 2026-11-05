#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::{
    dlfcn_abi as dl, errno_abi as errno, malloc_abi as allocation, mmap_abi as mapping,
    string_abi as strings, unistd_abi as unistd,
};
use frankenlibc_core::elf::ElfLoader;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
type Sym = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type Run = unsafe extern "C" fn() -> c_int;
type Function = unsafe extern "C" fn(u32) -> *mut c_void;
type Dynamic = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;

const SOURCE: &str = r#"#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef LOCAL_COMPARE
int memcmp(const void *left, const void *right, size_t n) {
    (void)left; (void)right; (void)n; return -23;
}
#endif
int memory_compare(void) { return memcmp("a", "b", 1); }
extern int memory_unknown_weak(void) __attribute__((weak));
int memory_weak_missing(void) { return memory_unknown_weak == 0; }
#ifdef STRONG_MISSING
extern int frankenlibc_memory_unknown_strong(void);
int memory_strong_missing(void) { return frankenlibc_memory_unknown_strong(); }
#endif

int memory_allocations(void) {
    unsigned char *p = calloc(64, 1);
    if (!p) return 1;
    for (int i = 0; i < 64; ++i) if (p[i] != 0) { free(p); return 2; }
    p[17] = 169;
    unsigned char *q = realloc(p, 512);
    if (!q) { free(p); return 3; }
    if (q[17] != 169 || malloc_usable_size(q) < 512) { free(q); return 4; }
    free(q);
    volatile size_t huge = SIZE_MAX;
    p = calloc(huge, 2);
    if (p) { free(p); return 5; }
    char *a = strdup("native-memory");
    char *b = strndup("native-memory", 6);
    int result = !a || !b || strcmp(a, "native-memory") || strcmp(b, "native");
    free(a); free(b);
    if (result) return 6;
    p = realloc(NULL, 37);
    if (!p) return 7;
    free(p);
    return 0;
}

int memory_strings(void) {
    const char s[] = "ab:abc:xyz";
    if (memchr(s, ':', 9) != s + 2 || memrchr(s, ':', 9) != s + 6) return 1;
    if (strchr(s, ':') != s + 2 || strrchr(s, ':') != s + 6) return 2;
    if (memcmp("abc", "abd", 3) >= 0 || strncmp("abc", "abd", 2) != 0) return 3;
    if (strnlen(s, 4) != 4 || strstr(s, "abc") != s + 3) return 4;
    if (strspn("aaab12", "ab") != 4 || strcspn("aab:cd", ":") != 3) return 5;
    const char accept[] = "ab:cd";
    if (strpbrk(accept, "x:") != accept + 2) return 6;
    char output[32]; memset(output, 165, sizeof output);
    if (strcpy(output, "abc") != output || strcmp(output, "abc")) return 7;
    if (strncpy(output, "x", 4) != output) return 8;
    if (output[0] != 'x' || output[1] || output[2] || output[3]) return 9;
    if (strcat(output, "yz") != output || strncat(output, "abcd", 2) != output) return 10;
    if (strcmp(output, "xyzab")) return 11;
    return 0;
}


#define VM_PAGE 4096
#define VM_CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)

#ifdef LOCAL_ADVICE
int madvise(void *address, size_t length, int advice) {
    (void)address; (void)length; (void)advice; return 23;
}
#endif
int memory_advice_probe(void) { return madvise(NULL, 0, MADV_NORMAL); }

int memory_virtual_mappings(void) {
    errno = 1234;
    VM_CHECK(getpagesize() == VM_PAGE && errno == 1234);
    VM_CHECK(sysconf(_SC_PAGESIZE) == VM_PAGE && errno == 1234);
    unsigned char *p = mmap(NULL, 2 * VM_PAGE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    VM_CHECK(p != MAP_FAILED && errno == 1234);
    for (int i = 0; i < 2 * VM_PAGE; ++i) VM_CHECK(p[i] == 0);
    p[0] = 41; p[VM_PAGE - 1] = 42; p[VM_PAGE] = 43; p[2 * VM_PAGE - 1] = 44;
    unsigned char resident[3] = {0, 0, 0xA5};
    VM_CHECK(mincore(p, 2 * VM_PAGE, resident) == 0 && resident[2] == 0xA5);
    VM_CHECK((resident[0] & 1) && (resident[1] & 1));
    VM_CHECK(mprotect(p, VM_PAGE, PROT_READ) == 0);
    VM_CHECK(p[0] == 41 && p[VM_PAGE - 1] == 42);
    VM_CHECK(mprotect(p, VM_PAGE, PROT_READ | PROT_WRITE) == 0);
    p[0] = 45;
    VM_CHECK(madvise(p, 2 * VM_PAGE, MADV_NORMAL) == 0);
    errno = 1234;
    VM_CHECK(posix_madvise(p, 2 * VM_PAGE, POSIX_MADV_NORMAL) == 0 && errno == 1234);
    /* POSIX_MADV_DONTNEED is nondestructive, unlike Linux MADV_DONTNEED. */
    VM_CHECK(posix_madvise(p, 2 * VM_PAGE, POSIX_MADV_DONTNEED) == 0);
    VM_CHECK(p[0] == 45 && p[VM_PAGE] == 43);
    /* Exercise the ordinary four-argument call as well as MREMAP_FIXED below. */
    unsigned char *q = mremap(p, 2 * VM_PAGE, 3 * VM_PAGE, MREMAP_MAYMOVE);
    VM_CHECK(q != MAP_FAILED && q[0] == 45 && q[VM_PAGE] == 43);
    VM_CHECK(q[VM_PAGE - 1] == 42 && q[2 * VM_PAGE - 1] == 44);
    for (int i = 2 * VM_PAGE; i < 3 * VM_PAGE; ++i) VM_CHECK(q[i] == 0);
    q[2 * VM_PAGE] = 46;
    VM_CHECK(madvise(q + 2 * VM_PAGE, VM_PAGE, MADV_DONTNEED) == 0);
    VM_CHECK(q[2 * VM_PAGE] == 0 && q[0] == 45);
    VM_CHECK(munlock(q, 3 * VM_PAGE) == 0);
    VM_CHECK(munmap(q, 3 * VM_PAGE) == 0);
    return 0;
}

int memory_fixed_remap(void) {
    unsigned char *p = mmap(NULL, VM_PAGE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    VM_CHECK(p != MAP_FAILED); p[0] = 83; p[VM_PAGE - 1] = 84;
    unsigned char *target = mmap(NULL, 2 * VM_PAGE, PROT_NONE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    VM_CHECK(target != MAP_FAILED);
    unsigned char *q = mremap(p, VM_PAGE, 2 * VM_PAGE,
                              MREMAP_MAYMOVE | MREMAP_FIXED, target);
    VM_CHECK(q == target && q[0] == 83 && q[VM_PAGE - 1] == 84 && q[VM_PAGE] == 0);
    unsigned char resident = 0xA5;
    errno = 0;
    VM_CHECK(mincore(p, VM_PAGE, &resident) == -1 && errno == ENOMEM);
    VM_CHECK(resident == 0xA5);
    VM_CHECK(munmap(q, 2 * VM_PAGE) == 0);
    return 0;
}

int memory_file_mappings(int fd) {
    VM_CHECK(ftruncate(fd, 2 * VM_PAGE) == 0);
    VM_CHECK(pwrite(fd, "A", 1, 0) == 1 && pwrite(fd, "B", 1, VM_PAGE) == 1);
    VM_CHECK(lseek(fd, 17, SEEK_SET) == 17);
    unsigned char *shared = mmap(NULL, 2 * VM_PAGE, PROT_READ | PROT_WRITE,
                                 MAP_SHARED, fd, 0);
    VM_CHECK(shared != MAP_FAILED && shared[0] == 'A' && shared[VM_PAGE] == 'B');
    unsigned char *private = mmap64(NULL, VM_PAGE, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE, fd, VM_PAGE);
    VM_CHECK(private != MAP_FAILED && private[0] == 'B');
    private[0] = 0x83;
    char byte = 0;
    VM_CHECK(pread(fd, &byte, 1, VM_PAGE) == 1 && byte == 'B');
    VM_CHECK(shared[VM_PAGE] == 'B');
    shared[0] = 'Q'; shared[VM_PAGE] = 'R';
    VM_CHECK(msync(shared, 2 * VM_PAGE, MS_SYNC) == 0);
    VM_CHECK(pread(fd, &byte, 1, 0) == 1 && byte == 'Q');
    VM_CHECK(pread(fd, &byte, 1, VM_PAGE) == 1 && byte == 'R');
    VM_CHECK(private[0] == 0x83 && lseek(fd, 0, SEEK_CUR) == 17);
    VM_CHECK(munmap(private, VM_PAGE) == 0 && munmap(shared, 2 * VM_PAGE) == 0);
    return 0;
}

int memory_mapping_errors(void) {
    unsigned char *p = mmap(NULL, VM_PAGE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    VM_CHECK(p != MAP_FAILED); p[0] = 71;
    errno = 0;
    VM_CHECK(mmap(NULL, 0, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
             == MAP_FAILED && errno == EINVAL);
    errno = 0;
    VM_CHECK(mmap64(NULL, VM_PAGE, PROT_READ, MAP_PRIVATE, -1, 0)
             == MAP_FAILED && errno == EBADF);
    errno = 0;
    VM_CHECK(mmap64(NULL, VM_PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 1)
             == MAP_FAILED && errno == EINVAL);
    errno = 0;
    VM_CHECK(munmap(p + 1, VM_PAGE) == -1 && errno == EINVAL && p[0] == 71);
    errno = 0;
    VM_CHECK(mprotect(p + 1, VM_PAGE - 1, PROT_READ) == -1 && errno == EINVAL);
    p[0] = 72; /* A failed protection change must leave the mapping writable. */
    errno = 0;
    VM_CHECK(msync(p + 1, VM_PAGE - 1, MS_SYNC) == -1 && errno == EINVAL);
    errno = 0;
    VM_CHECK(madvise(p + 1, VM_PAGE - 1, MADV_NORMAL) == -1 && errno == EINVAL);
    errno = 1234;
    VM_CHECK(posix_madvise(p + 1, VM_PAGE - 1, POSIX_MADV_NORMAL) == EINVAL);
    VM_CHECK(errno == 1234 && p[0] == 72);
    unsigned char resident[2] = {0xA5, 0xA5};
    errno = 0;
    VM_CHECK(mincore(p + 1, VM_PAGE - 1, resident) == -1 && errno == EINVAL);
    VM_CHECK(resident[0] == 0xA5 && resident[1] == 0xA5);
    errno = 0;
    VM_CHECK(mremap(p, VM_PAGE, 0, MREMAP_MAYMOVE) == MAP_FAILED && errno == EINVAL);
    VM_CHECK(p[0] == 72);
    errno = 0;
    VM_CHECK(mlockall(0) == -1 && errno == EINVAL);
    errno = 0;
    VM_CHECK(mlock2(p, VM_PAGE, -1) == -1 && errno == EINVAL);
    VM_CHECK(munmap(p, VM_PAGE) == 0);
    return 0;
}

/* The parent expects SIGSEGV, so a no-op mprotect cannot pass this protocol. */
int memory_write_readonly(void) {
    volatile unsigned char *p = mmap(NULL, VM_PAGE, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    VM_CHECK((void *)p != MAP_FAILED);
    VM_CHECK(mprotect((void *)p, VM_PAGE, PROT_READ) == 0);
    p[0] = 1;
    return 0;
}

void *memory_function(unsigned index) {
    switch (index) {
        case 0: return (void *)calloc;
        case 1: return (void *)realloc;
        case 2: return (void *)malloc_usable_size;
        case 3: return (void *)memchr;
        case 4: return (void *)memrchr;
        case 5: return (void *)memcmp;
        case 6: return (void *)strchr;
        case 7: return (void *)strrchr;
        case 8: return (void *)strncmp;
        case 9: return (void *)strnlen;
        case 10: return (void *)strstr;
        case 11: return (void *)strdup;
        case 12: return (void *)strndup;
        case 13: return (void *)strcpy;
        case 14: return (void *)strncpy;
        case 15: return (void *)strcat;
        case 16: return (void *)strncat;
        case 17: return (void *)strspn;
        case 18: return (void *)strcspn;
        case 19: return (void *)strpbrk;
        case 20: return (void *)malloc;
        case 21: return (void *)free;
        case 22: return (void *)mmap;
        case 23: return (void *)mmap64;
        case 24: return (void *)munmap;
        case 25: return (void *)mprotect;
        case 26: return (void *)msync;
        case 27: return (void *)madvise;
        case 28: return (void *)posix_madvise;
        case 29: return (void *)mincore;
        case 30: return (void *)mremap;
        case 31: return (void *)mlock;
        case 32: return (void *)munlock;
        case 33: return (void *)mlockall;
        case 34: return (void *)munlockall;
        case 35: return (void *)mlock2;
        case 36: return (void *)__errno_location;
        case 37: return (void *)getpagesize;
        case 38: return (void *)sysconf;
        default: return 0;
    }
}
void *memory_dynamic(const char *name, const char *version) {
    return version ? dlvsym(RTLD_DEFAULT, name, version) : dlsym(RTLD_DEFAULT, name);
}
#ifdef LIFECYCLE
int memory_init_result = -1;
static void (*memory_report)(int);
__attribute__((constructor)) static void init(void) { memory_init_result = memory_allocations(); }
void memory_set_report(void (*report)(int)) { memory_report = report; }
__attribute__((destructor)) static void fini(void) {
    int result = memory_allocations(); if (memory_report) memory_report(result);
}
#endif
"#;

fn symbols() -> [(&'static str, *const ()); 39] {
    [
        ("calloc", allocation::calloc as *const ()),
        ("realloc", allocation::realloc as *const ()),
        (
            "malloc_usable_size",
            allocation::malloc_usable_size as *const (),
        ),
        ("memchr", strings::memchr as *const ()),
        ("memrchr", strings::memrchr as *const ()),
        ("memcmp", strings::memcmp as *const ()),
        ("strchr", strings::strchr as *const ()),
        ("strrchr", strings::strrchr as *const ()),
        ("strncmp", strings::strncmp as *const ()),
        ("strnlen", strings::strnlen as *const ()),
        ("strstr", strings::strstr as *const ()),
        ("strdup", strings::strdup as *const ()),
        ("strndup", strings::strndup as *const ()),
        ("strcpy", strings::strcpy as *const ()),
        ("strncpy", strings::strncpy as *const ()),
        ("strcat", strings::strcat as *const ()),
        ("strncat", strings::strncat as *const ()),
        ("strspn", strings::strspn as *const ()),
        ("strcspn", strings::strcspn as *const ()),
        ("strpbrk", strings::strpbrk as *const ()),
        ("malloc", allocation::malloc as *const ()),
        ("free", allocation::free as *const ()),
        ("mmap", mapping::mmap as *const ()),
        ("mmap64", unistd::mmap64 as *const ()),
        ("munmap", mapping::munmap as *const ()),
        ("mprotect", mapping::mprotect as *const ()),
        ("msync", mapping::msync as *const ()),
        ("madvise", mapping::madvise as *const ()),
        ("posix_madvise", unistd::posix_madvise as *const ()),
        ("mincore", unistd::mincore as *const ()),
        ("mremap", mapping::mremap as *const ()),
        ("mlock", mapping::mlock as *const ()),
        ("munlock", mapping::munlock as *const ()),
        ("mlockall", mapping::mlockall as *const ()),
        ("munlockall", mapping::munlockall as *const ()),
        ("mlock2", mapping::mlock2 as *const ()),
        ("__errno_location", errno::__errno_location as *const ()),
        ("getpagesize", unistd::getpagesize as *const ()),
        ("sysconf", unistd::sysconf as *const ()),
    ]
}

#[derive(Clone, Copy)]
struct Api {
    open: Open,
    close: Close,
    sym: Sym,
    native: bool,
}
impl Api {
    fn new(native: bool) -> Self {
        if native {
            Self {
                open: dl::dlopen,
                close: dl::dlclose,
                sym: dl::dlsym,
                native,
            }
        } else {
            unsafe {
                Self {
                    open: dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ()),
                    close: dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ()),
                    sym: dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ()),
                    native,
                }
            }
        }
    }
    fn open(self, path: &Path, flags: c_int) -> *mut c_void {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(name.as_ptr(), flags | libc::RTLD_NOW) };
        assert!(!handle.is_null(), "open {path:?}");
        if self.native {
            assert!(dl::native_dso_handle_for_tests(handle), "host fallback");
        }
        handle
    }
    fn close(self, handle: *mut c_void) {
        assert_eq!(unsafe { (self.close)(handle) }, 0);
    }
    fn symbol(self, handle: *mut c_void, name: &CStr) -> *mut c_void {
        let value = unsafe { (self.sym)(handle, name.as_ptr()) };
        assert!(!value.is_null(), "symbol {name:?}");
        value
    }
    fn run(self, handle: *mut c_void, name: &CStr) -> c_int {
        let run: Run = unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { run() }
    }
}

struct Fixture {
    dir: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new(flags: &[&str]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc-memory-runtime-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("fixture.c");
        let path = dir.join("fixture.so");
        std::fs::write(&source, SOURCE).unwrap();
        compile(&source, &path, flags);
        let object = ElfLoader::new(0)
            .parse(&std::fs::read(&path).unwrap())
            .unwrap();
        assert!(
            object.needed_libraries.is_empty(),
            "fixture must not import a host runtime"
        );
        for (name, _) in symbols() {
            assert!(
                object
                    .dynsym
                    .iter()
                    .any(|s| object.symbol_name(s) == Some(name)),
                "missing {name}"
            );
        }
        Self { dir, path }
    }
}

fn compile(source: &Path, output: &Path, flags: &[&str]) {
    let result = Command::new("gcc")
        .args([
            "-shared",
            "-fPIC",
            "-nostdlib",
            "-O2",
            "-fno-builtin",
            "-Wl,--hash-style=both",
        ])
        .args(flags)
        .arg(source)
        .arg("-o")
        .arg(output)
        .output()
        .expect("gcc is required");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn isolated(name: &str, native_only: bool, scenario: fn(Api)) {
    if let Ok(mode) = std::env::var("FRANKENLIBC_MEMORY_CHILD") {
        assert!(matches!(mode.as_str(), "host" | "native"));
        scenario(Api::new(mode == "native"));
        return;
    }
    let modes: &[&str] = if native_only {
        &["native"]
    } else {
        &["host", "native"]
    };
    for mode in modes {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FRANKENLIBC_MEMORY_CHILD", mode)
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{name}: {mode}: {status}");
                break;
            }
            if start.elapsed() > Duration::from_secs(40) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{name}: {mode}: timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn assert_memory_providers(api: Api, handle: *mut c_void) {
    let function: Function = unsafe { std::mem::transmute(api.symbol(handle, c"memory_function")) };
    for (index, (name, expected)) in symbols().into_iter().enumerate() {
        let actual = unsafe { function(index as u32) };
        assert!(!actual.is_null(), "missing runtime {name}");
        if api.native {
            assert_eq!(actual as usize, expected as usize, "wrong provider: {name}");
        } else {
            let name = CString::new(name).unwrap();
            let host = unsafe { dlsym_oracle::host_addr(&name, expected) };
            assert_eq!(actual, host);
        }
    }
}

fn exercise(api: Api, flags: &[&str]) {
    let fixture = Fixture::new(flags);
    let handle = api.open(&fixture.path, 0);
    assert_memory_providers(api, handle);
    assert_eq!(api.run(handle, c"memory_allocations"), 0);
    assert_eq!(api.run(handle, c"memory_strings"), 0);
    assert_eq!(api.run(handle, c"memory_virtual_mappings"), 0);
    assert_eq!(api.run(handle, c"memory_fixed_remap"), 0);
    assert_eq!(api.run(handle, c"memory_mapping_errors"), 0);
    assert_eq!(api.run(handle, c"memory_weak_missing"), 1);
    api.close(handle);
}

#[test]
fn memory_runtime_plt_calls_reach_owned_implementations() {
    isolated(
        "memory_runtime_plt_calls_reach_owned_implementations",
        false,
        |api| exercise(api, &[]),
    );
}

#[test]
fn memory_runtime_got_calls_reach_owned_implementations() {
    isolated(
        "memory_runtime_got_calls_reach_owned_implementations",
        false,
        |api| exercise(api, &["-fno-plt"]),
    );
}

#[test]
fn memory_runtime_dynamic_addresses_match_direct_imports() {
    isolated(
        "memory_runtime_dynamic_addresses_match_direct_imports",
        false,
        |api| {
            let f = Fixture::new(&[]);
            let h = api.open(&f.path, 0);
            assert_memory_providers(api, h);
            let imported: Function =
                unsafe { std::mem::transmute(api.symbol(h, c"memory_function")) };
            let dynamic: Dynamic = unsafe { std::mem::transmute(api.symbol(h, c"memory_dynamic")) };
            for (index, (name, expected)) in symbols().into_iter().enumerate() {
                let valid_version = if name == "mlock2" {
                    c"GLIBC_2.27"
                } else {
                    c"GLIBC_2.2.5"
                };
                let wrong_version = if name == "mlock2" {
                    c"GLIBC_2.2.5"
                } else {
                    c"GLIBC_2.27"
                };
                let name = CString::new(name).unwrap();
                let direct = unsafe { imported(index as u32) };
                if api.native {
                    assert_eq!(direct as usize, expected as usize);
                }
                for version in [std::ptr::null(), valid_version.as_ptr()] {
                    assert_eq!(unsafe { dynamic(name.as_ptr(), version) }, direct);
                }
                for version in [wrong_version, c"GLIBC_2.34", c"FRANKENLIBC_NO_SUCH_VERSION"] {
                    assert!(unsafe { dynamic(name.as_ptr(), version.as_ptr()) }.is_null());
                }
            }
            api.close(h);
        },
    );
}

static FINAL_RESULT: AtomicI32 = AtomicI32::new(-100);
unsafe extern "C" fn final_report(result: c_int) {
    FINAL_RESULT.store(result, Ordering::Relaxed);
}

#[test]
fn memory_runtime_is_available_during_construction_and_finalization() {
    isolated(
        "memory_runtime_is_available_during_construction_and_finalization",
        false,
        |api| {
            let f = Fixture::new(&["-DLIFECYCLE"]);
            let h = api.open(&f.path, 0);
            assert_eq!(
                unsafe { *api.symbol(h, c"memory_init_result").cast::<i32>() },
                0
            );
            type Set = unsafe extern "C" fn(unsafe extern "C" fn(c_int));
            let set: Set = unsafe { std::mem::transmute(api.symbol(h, c"memory_set_report")) };
            unsafe { set(final_report) };
            api.close(h);
            assert_eq!(FINAL_RESULT.load(Ordering::Relaxed), 0);
        },
    );
}

#[test]
fn memory_runtime_missing_strong_import_does_not_publish_a_handle() {
    isolated(
        "memory_runtime_missing_strong_import_does_not_publish_a_handle",
        false,
        |api| {
            let f = Fixture::new(&["-DSTRONG_MISSING"]);
            let name = CString::new(f.path.as_os_str().as_bytes()).unwrap();
            assert!(unsafe { (api.open)(name.as_ptr(), libc::RTLD_NOW) }.is_null());
            assert!(
                unsafe { (api.open)(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) }.is_null()
            );
            let valid = Fixture::new(&[]);
            let h = api.open(&valid.path, 0);
            assert_eq!(api.run(h, c"memory_allocations"), 0);
            api.close(h);
        },
    );
}

#[test]
fn memory_runtime_fallback_preserves_native_scope_preemption() {
    // This tests the native namespace's existing GLOBAL/local binding policy,
    // not glibc's executable/libc prefix ordering for a standard libc name.
    isolated(
        "memory_runtime_fallback_preserves_native_scope_preemption",
        true,
        |api| {
            let ordinary = Fixture::new(&["-DLOCAL_COMPARE"]);
            let provider_c = ordinary.dir.join("provider.c");
            let provider_so = ordinary.dir.join("provider.so");
            std::fs::write(&provider_c, "#include <stddef.h>\nint memcmp(const void*a,const void*b,size_t n){(void)a;(void)b;(void)n;return 37;}\n").unwrap();
            compile(&provider_c, &provider_so, &[]);
            let g = api.open(&provider_so, libc::RTLD_GLOBAL);
            let h = api.open(&ordinary.path, 0);
            assert_eq!(api.run(h, c"memory_compare"), 37);
            let selected = api.symbol(g, c"memcmp");
            let dynamic: Dynamic = unsafe { std::mem::transmute(api.symbol(h, c"memory_dynamic")) };
            assert_eq!(
                unsafe { dynamic(c"memcmp".as_ptr(), std::ptr::null()) },
                selected
            );
            let deep = Fixture::new(&["-DLOCAL_COMPARE"]);
            let d = api.open(&deep.path, libc::RTLD_DEEPBIND);
            assert_eq!(api.run(d, c"memory_compare"), -23);
            let own = api.symbol(d, c"memcmp");
            let deep_dynamic: Dynamic =
                unsafe { std::mem::transmute(api.symbol(d, c"memory_dynamic")) };
            assert_eq!(
                unsafe { deep_dynamic(c"memcmp".as_ptr(), std::ptr::null()) },
                own
            );
            api.close(g);
            assert_eq!(api.run(h, c"memory_compare"), 37);
            api.close(h);
            api.close(d);
        },
    );
}

#[test]
fn memory_runtime_shared_and_private_file_mappings_preserve_io_state() {
    isolated(
        "memory_runtime_shared_and_private_file_mappings_preserve_io_state",
        false,
        |api| {
            let fixture = Fixture::new(&[]);
            let handle = api.open(&fixture.path, 0);
            assert_memory_providers(api, handle);
            let pathname = fixture.dir.join("mapped-file");
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&pathname)
                .unwrap();
            type FileMappings = unsafe extern "C" fn(c_int) -> c_int;
            let run: FileMappings =
                unsafe { std::mem::transmute(api.symbol(handle, c"memory_file_mappings")) };
            assert_eq!(unsafe { run(file.as_raw_fd()) }, 0);
            // Read through the independent host file API after both mappings
            // were unmapped: copying bytes only inside the plugin cannot pass.
            let bytes = std::fs::read(&pathname).unwrap();
            assert_eq!(bytes.len(), 8192);
            assert_eq!(bytes[0], b'Q');
            assert_eq!(bytes[4096], b'R');
            assert!(bytes[1..4096].iter().all(|byte| *byte == 0));
            assert!(bytes[4097..].iter().all(|byte| *byte == 0));
            api.close(handle);
        },
    );
}

#[test]
fn memory_runtime_vm_fallback_preserves_native_scope_preemption() {
    // As with the allocation/string test above, this exercises the native
    // namespace, whose GLOBAL prefix is separate from the host libc prefix.
    isolated(
        "memory_runtime_vm_fallback_preserves_native_scope_preemption",
        true,
        |api| {
            let ordinary = Fixture::new(&["-DLOCAL_ADVICE"]);
            let provider_c = ordinary.dir.join("vm-provider.c");
            let provider_so = ordinary.dir.join("vm-provider.so");
            std::fs::write(
                &provider_c,
                "#include <stddef.h>\nint madvise(void *a,size_t n,int v){(void)a;(void)n;(void)v;return 37;}\n",
            )
            .unwrap();
            compile(&provider_c, &provider_so, &[]);
            let global = api.open(&provider_so, libc::RTLD_GLOBAL);
            let handle = api.open(&ordinary.path, 0);
            let selected = api.symbol(global, c"madvise");
            let imported: Function =
                unsafe { std::mem::transmute(api.symbol(handle, c"memory_function")) };
            assert_eq!(unsafe { imported(27) }, selected);
            assert_eq!(api.run(handle, c"memory_advice_probe"), 37);
            let dynamic: Dynamic =
                unsafe { std::mem::transmute(api.symbol(handle, c"memory_dynamic")) };
            assert_eq!(
                unsafe { dynamic(c"madvise".as_ptr(), std::ptr::null()) },
                selected
            );
            let deep = Fixture::new(&["-DLOCAL_ADVICE"]);
            let deep_handle = api.open(&deep.path, libc::RTLD_DEEPBIND);
            let local = api.symbol(deep_handle, c"madvise");
            assert_ne!(local, selected);
            assert_eq!(api.run(deep_handle, c"memory_advice_probe"), 23);
            let deep_dynamic: Dynamic =
                unsafe { std::mem::transmute(api.symbol(deep_handle, c"memory_dynamic")) };
            assert_eq!(
                unsafe { deep_dynamic(c"madvise".as_ptr(), std::ptr::null()) },
                local
            );
            api.close(global);
            assert_eq!(api.run(handle, c"memory_advice_probe"), 37);
            api.close(handle);
            api.close(deep_handle);
        },
    );
}

#[test]
fn memory_runtime_protection_changes_fault_on_write() {
    const NAME: &str = "memory_runtime_protection_changes_fault_on_write";
    if let Ok(mode) = std::env::var("FRANKENLIBC_MEMORY_FAULT_CHILD") {
        assert!(matches!(mode.as_str(), "host" | "native"));
        let api = Api::new(mode == "native");
        let fixture = Fixture::new(&[]);
        let handle = api.open(&fixture.path, 0);
        assert_memory_providers(api, handle);
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: this isolated child intentionally faults below. Disabling
        // its core dump affects no other process or test.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) }, 0);
        let result = api.run(handle, c"memory_write_readonly");
        panic!("write to read-only mapping unexpectedly returned {result}");
    }
    for mode in ["host", "native"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env("FRANKENLIBC_MEMORY_FAULT_CHILD", mode)
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert_eq!(status.signal(), Some(libc::SIGSEGV), "{mode}: {status}");
                break;
            }
            if start.elapsed() > Duration::from_secs(40) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{NAME}: {mode}: timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
