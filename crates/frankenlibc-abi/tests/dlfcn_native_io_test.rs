#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicI32;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::{dlfcn_abi as dl, errno_abi as errno, io_abi as io, unistd_abi as unistd};
use frankenlibc_core::elf::ElfLoader;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
type Sym = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type Function = unsafe extern "C" fn(u32) -> *mut c_void;
type Dynamic = unsafe extern "C" fn(*const c_char, *const c_char, *mut c_int) -> *mut c_void;

const SOURCE: &str = r#"#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <unistd.h>
#define CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)

int io_file_protocol(const char *directory, const char *pathname) {
    int fd = creat(pathname, 0600);
    CHECK(fd >= 0); CHECK(close(fd) == 0);
    fd = open(pathname, O_RDWR); CHECK(fd >= 0);
    char a[] = "ab", b[] = "cdef";
    struct iovec out[2] = {{a, 2}, {b, 4}};
    CHECK(writev(fd, out, 2) == 6);
    CHECK(lseek(fd, 1, SEEK_SET) == 1);
    CHECK(pwrite(fd, "XY", 2, 2) == 2);
    CHECK(lseek(fd, 0, SEEK_CUR) == 1);
    char peek[3] = {0, 0, 0};
    CHECK(pread(fd, peek, 2, 2) == 2 && peek[0] == 'X' && peek[1] == 'Y');
    CHECK(pwrite64(fd, "Z", 1, 4) == 1);
    CHECK(pread64(fd, peek, 1, 4) == 1 && peek[0] == 'Z');
    CHECK(lseek64(fd, 0, SEEK_CUR) == 1);
    CHECK(lseek64(fd, 0, SEEK_SET) == 0);
    char left[2] = {0, 0}, right[5] = {0, 0, 0, 0, 99};
    struct iovec in[2] = {{left, 2}, {right, 4}};
    CHECK(readv(fd, in, 2) == 6);
    CHECK(left[0] == 'a' && left[1] == 'b');
    CHECK(right[0] == 'X' && right[1] == 'Y' && right[2] == 'Z' && right[3] == 'f' && right[4] == 99);
    CHECK(ftruncate(fd, 10) == 0);
    char zero[5] = {1, 1, 1, 1, 88};
    CHECK(pread(fd, zero, 4, 6) == 4);
    CHECK(zero[0] == 0 && zero[1] == 0 && zero[2] == 0 && zero[3] == 0 && zero[4] == 88);
    CHECK(ftruncate64(fd, 4) == 0);
    CHECK(fsync(fd) == 0 && fdatasync(fd) == 0);
    CHECK(close(fd) == 0);
    fd = open64(pathname, O_RDONLY); CHECK(fd >= 0);
    CHECK(lseek64(fd, 0, SEEK_END) == 4); CHECK(close(fd) == 0);
    int dir = open(directory, O_RDONLY | O_DIRECTORY); CHECK(dir >= 0);
    fd = openat(dir, "at-file", O_CREAT | O_EXCL | O_RDWR, 0600); CHECK(fd >= 0);
    CHECK(write(fd, "q", 1) == 1); CHECK(close(fd) == 0);
    fd = openat64(dir, "at-file", O_RDONLY); CHECK(fd >= 0);
    CHECK(read(fd, peek, 1) == 1 && peek[0] == 'q');
    CHECK(close(fd) == 0); CHECK(close(dir) == 0);
    return 0;
}

int io_descriptor_protocol(const char *pathname) {
    int fd = open(pathname, O_CREAT | O_TRUNC | O_RDWR, 0600); CHECK(fd >= 0);
    /* Exercise genuinely variadic calls with no argument, an integer, and
       a pointer. Native bindings must keep both fcntl names in one domain. */
    CHECK(fcntl(fd, F_GETFD) == 0);
    CHECK(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
    CHECK(fcntl64(fd, F_GETFD) == FD_CLOEXEC);
    CHECK(fcntl64(fd, F_SETFD, 0) == 0 && fcntl(fd, F_GETFD) == 0);
    int flags = fcntl(fd, F_GETFL); CHECK(flags >= 0);
    CHECK(fcntl64(fd, F_SETFL, flags | O_NONBLOCK) == 0);
    CHECK(fcntl(fd, F_GETFL) & O_NONBLOCK);
    CHECK(fcntl(fd, F_SETFL, flags) == 0);
    int cloexec = fcntl64(fd, F_DUPFD_CLOEXEC, 0); CHECK(cloexec >= 0);
    CHECK(fcntl(cloexec, F_GETFD) == FD_CLOEXEC);
    CHECK(close(cloexec) == 0);
    CHECK(flock(fd, LOCK_EX | LOCK_NB) == 0);
    int independent = open(pathname, O_RDWR); CHECK(independent >= 0);
    errno = 0;
    CHECK(flock(independent, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK);
    CHECK(flock(fd, LOCK_UN) == 0);
    CHECK(flock(independent, LOCK_EX | LOCK_NB) == 0);
    CHECK(flock(independent, LOCK_UN) == 0 && close(independent) == 0);
    struct flock record = { .l_type = F_WRLCK, .l_whence = SEEK_SET,
                            .l_start = 0, .l_len = 8 };
    CHECK(fcntl64(fd, F_SETLK, &record) == 0);
    record.l_type = F_UNLCK;
    CHECK(fcntl(fd, F_SETLK, &record) == 0);
    CHECK(lockf(fd, F_TLOCK, 8) == 0);
    CHECK(lockf64(fd, F_ULOCK, 8) == 0);
    errno = 1234;
    CHECK(posix_fallocate(fd, 0, 16) == 0 && errno == 1234);
    CHECK(posix_fallocate64(fd, 16, 16) == 0 && errno == 1234);
    CHECK(lseek(fd, 0, SEEK_END) == 32);
    CHECK(posix_fadvise(fd, 0, 32, POSIX_FADV_SEQUENTIAL) == 0);
    CHECK(posix_fadvise64(fd, 0, 32, POSIX_FADV_DONTNEED) == 0);
    errno = 1234;
    CHECK(posix_fallocate(fd, 0, -1) == EINVAL && errno == 1234);
    CHECK(posix_fadvise64(fd, 0, 32, -1) == EINVAL && errno == 1234);
    CHECK(ftruncate(fd, 0) == 0 && lseek(fd, 0, SEEK_SET) == 0);
    CHECK(write(fd, "012345", 6) == 6); CHECK(lseek(fd, 0, SEEK_SET) == 0);
    int shared = dup(fd); CHECK(shared >= 0 && shared != fd);
    char value = 0; CHECK(read(shared, &value, 1) == 1 && value == '0');
    CHECK(lseek(fd, 0, SEEK_CUR) == 1);
    int target = open("/dev/null", O_RDONLY); CHECK(target >= 0);
    CHECK(dup2(fd, target) == target); CHECK(read(target, &value, 1) == 1 && value == '1');
    CHECK(dup2(fd, fd) == fd);
    CHECK(dup3(fd, target, O_CLOEXEC) == target);
    CHECK(read(target, &value, 1) == 1 && value == '2');
    errno = 0; CHECK(dup3(fd, fd, 0) == -1 && errno == EINVAL);
    CHECK(close(target) == 0 && close(shared) == 0 && close(fd) == 0);
    int ends[2]; CHECK(pipe(ends) == 0);
    CHECK(fcntl64(ends[0], F_SETFL, fcntl(ends[0], F_GETFL) | O_NONBLOCK) == 0);
    errno = 0; value = 85;
    CHECK(read(ends[0], &value, 1) == -1 && errno == EAGAIN && value == 85);
    CHECK(write(ends[1], "p", 1) == 1 && read(ends[0], &value, 1) == 1 && value == 'p');
    CHECK(close(ends[1]) == 0 && read(ends[0], &value, 1) == 0 && close(ends[0]) == 0);
    CHECK(pipe2(ends, O_NONBLOCK | O_CLOEXEC) == 0);
    errno = 0; value = 85;
    CHECK(read(ends[0], &value, 1) == -1 && errno == EAGAIN && value == 85);
    CHECK(write(ends[1], "v", 1) == 1 && read(ends[0], &value, 1) == 1 && value == 'v');
    CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);
    return 0;
}

int io_error_protocol(const char *pathname) {
    char bytes[4] = {11, 22, 33, 44};
    errno = 0; CHECK(fcntl(-1, F_GETFD) == -1 && errno == EBADF);
    errno = 0; CHECK(fcntl64(-1, F_GETFL) == -1 && errno == EBADF);
    errno = 1234; CHECK(posix_fadvise(-1, 0, 1, POSIX_FADV_NORMAL) == EBADF && errno == 1234);
    CHECK(posix_fallocate64(-1, 0, 1) == EBADF && errno == 1234);
    errno = 0; CHECK(read(-1, bytes, 3) == -1 && errno == EBADF);
    CHECK(bytes[0] == 11 && bytes[1] == 22 && bytes[2] == 33 && bytes[3] == 44);
    errno = 0; CHECK(write(-1, bytes, 3) == -1 && errno == EBADF);
    int fd = open(pathname, O_CREAT | O_TRUNC | O_RDWR, 0600); CHECK(fd >= 0);
    CHECK(write(fd, "data", 4) == 4); CHECK(lseek(fd, 1, SEEK_SET) == 1);
    errno = 0; CHECK(lseek(fd, 0, 123456) == -1 && errno == EINVAL);
    CHECK(lseek(fd, 0, SEEK_CUR) == 1);
    errno = 0; CHECK(pread(fd, bytes, 3, -1) == -1 && errno == EINVAL);
    CHECK(bytes[0] == 11 && bytes[1] == 22 && bytes[2] == 33 && bytes[3] == 44);
    CHECK(lseek(fd, 0, SEEK_CUR) == 1);
    CHECK(pread(fd, bytes, 3, 3) == 1 && bytes[0] == 'a' && bytes[1] == 22 && bytes[2] == 33);
    CHECK(close(fd) == 0);
    errno = 0; CHECK(close(fd) == -1 && errno == EBADF);
    errno = 0; CHECK(openat(-1, "unavailable", O_RDONLY) == -1 && errno == EBADF);
    return 0;
}

uintptr_t io_thread_errno(int *arrived, int marker) {
    char byte;
    errno = 0;
    if (read(-1, &byte, 1) != -1 || errno != EBADF) return 0;
    int *slot = __errno_location(); *slot = marker;
    __atomic_add_fetch(arrived, 1, __ATOMIC_SEQ_CST);
    while (__atomic_load_n(arrived, __ATOMIC_SEQ_CST) != 2) { }
    return *slot == marker ? (uintptr_t)slot : 0;
}

void *io_function(unsigned index) {
    switch (index) {
        case 0: return (void *)__errno_location;
        case 1: return (void *)open;
        case 2: return (void *)open64;
        case 3: return (void *)openat;
        case 4: return (void *)openat64;
        case 5: return (void *)creat;
        case 6: return (void *)read;
        case 7: return (void *)write;
        case 8: return (void *)close;
        case 9: return (void *)lseek;
        case 10: return (void *)lseek64;
        case 11: return (void *)pread;
        case 12: return (void *)pread64;
        case 13: return (void *)pwrite;
        case 14: return (void *)pwrite64;
        case 15: return (void *)readv;
        case 16: return (void *)writev;
        case 17: return (void *)ftruncate;
        case 18: return (void *)ftruncate64;
        case 19: return (void *)fsync;
        case 20: return (void *)fdatasync;
        case 21: return (void *)dup;
        case 22: return (void *)dup2;
        case 23: return (void *)dup3;
        case 24: return (void *)pipe;
        case 25: return (void *)pipe2;
        case 26: return (void *)fcntl;
        case 27: return (void *)fcntl64;
        case 28: return (void *)flock;
        case 29: return (void *)lockf;
        case 30: return (void *)lockf64;
        case 31: return (void *)posix_fadvise;
        case 32: return (void *)posix_fadvise64;
        case 33: return (void *)posix_fallocate;
        case 34: return (void *)posix_fallocate64;
        default: return 0;
    }
}
void *io_dynamic(const char *name, const char *version, int *error) {
    dlerror();
    void *result = version ? dlvsym(RTLD_DEFAULT, name, version) : dlsym(RTLD_DEFAULT, name);
    *error = dlerror() != 0;
    __asm__ __volatile__("" : "+r"(result));
    return result;
}

static int init_result = -1;
static int final_fd = -1;
static int lifecycle_probe(void) {
    int ends[2]; char byte = 0;
    CHECK(pipe(ends) == 0);
    CHECK(write(ends[1], "L", 1) == 1 && read(ends[0], &byte, 1) == 1 && byte == 'L');
    CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);
    return 0;
}
__attribute__((constructor)) static void initialize(void) { init_result = lifecycle_probe(); }
int io_initial_result(void) { return init_result; }
int io_set_final_fd(int fd) { final_fd = dup(fd); return final_fd < 0 ? -1 : 0; }
__attribute__((destructor)) static void finalize(void) {
    if (final_fd >= 0) {
        char result = lifecycle_probe() == 0 ? 'F' : '!';
        if (write(final_fd, &result, 1) != 1) return;
        close(final_fd);
    }
}
"#;

fn symbols() -> [(&'static str, &'static str, *const ()); 35] {
    [
        (
            "__errno_location",
            "GLIBC_2.2.5",
            errno::__errno_location as *const (),
        ),
        ("open", "GLIBC_2.2.5", unistd::open as *const ()),
        ("open64", "GLIBC_2.2.5", unistd::open64 as *const ()),
        ("openat", "GLIBC_2.4", unistd::openat as *const ()),
        ("openat64", "GLIBC_2.4", unistd::openat64 as *const ()),
        ("creat", "GLIBC_2.2.5", unistd::creat as *const ()),
        ("read", "GLIBC_2.2.5", unistd::read as *const ()),
        ("write", "GLIBC_2.2.5", unistd::write as *const ()),
        ("close", "GLIBC_2.2.5", unistd::close as *const ()),
        ("lseek", "GLIBC_2.2.5", unistd::lseek as *const ()),
        ("lseek64", "GLIBC_2.2.5", unistd::lseek64 as *const ()),
        ("pread", "GLIBC_2.2.5", io::pread as *const ()),
        ("pread64", "GLIBC_2.2.5", unistd::pread64 as *const ()),
        ("pwrite", "GLIBC_2.2.5", io::pwrite as *const ()),
        ("pwrite64", "GLIBC_2.2.5", unistd::pwrite64 as *const ()),
        ("readv", "GLIBC_2.2.5", io::readv as *const ()),
        ("writev", "GLIBC_2.2.5", io::writev as *const ()),
        ("ftruncate", "GLIBC_2.2.5", unistd::ftruncate as *const ()),
        (
            "ftruncate64",
            "GLIBC_2.2.5",
            unistd::ftruncate64 as *const (),
        ),
        ("fsync", "GLIBC_2.2.5", unistd::fsync as *const ()),
        ("fdatasync", "GLIBC_2.2.5", unistd::fdatasync as *const ()),
        ("dup", "GLIBC_2.2.5", io::dup as *const ()),
        ("dup2", "GLIBC_2.2.5", io::dup2 as *const ()),
        ("dup3", "GLIBC_2.9", io::dup3 as *const ()),
        ("pipe", "GLIBC_2.2.5", io::pipe as *const ()),
        ("pipe2", "GLIBC_2.9", io::pipe2 as *const ()),
        ("fcntl", "GLIBC_2.2.5", unistd::fcntl64 as *const ()),
        ("fcntl64", "GLIBC_2.28", unistd::fcntl64 as *const ()),
        ("flock", "GLIBC_2.2.5", unistd::flock as *const ()),
        ("lockf", "GLIBC_2.2.5", unistd::lockf as *const ()),
        ("lockf64", "GLIBC_2.2.5", unistd::lockf64 as *const ()),
        (
            "posix_fadvise",
            "GLIBC_2.2.5",
            unistd::posix_fadvise as *const (),
        ),
        (
            "posix_fadvise64",
            "GLIBC_2.2.5",
            unistd::posix_fadvise64 as *const (),
        ),
        (
            "posix_fallocate",
            "GLIBC_2.2.5",
            unistd::posix_fallocate as *const (),
        ),
        (
            "posix_fallocate64",
            "GLIBC_2.2.5",
            unistd::posix_fallocate64 as *const (),
        ),
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
    fn open(self, path: &Path) -> *mut c_void {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let h = unsafe { (self.open)(name.as_ptr(), libc::RTLD_NOW) };
        assert!(!h.is_null(), "open {path:?}");
        if self.native {
            assert!(
                dl::native_dso_handle_for_tests(h),
                "host fallback: {path:?}"
            );
        }
        h
    }
    fn close(self, handle: *mut c_void) {
        assert_eq!(unsafe { (self.close)(handle) }, 0);
    }
    fn symbol(self, h: *mut c_void, name: &CStr) -> *mut c_void {
        let p = unsafe { (self.sym)(h, name.as_ptr()) };
        assert!(!p.is_null(), "missing {name:?}");
        p
    }
}

struct Fixture {
    dir: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new(got: bool) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc-native-io-{}-{}",
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
        let mut command = Command::new("gcc");
        command.args([
            "-shared",
            "-fPIC",
            "-nostdlib",
            "-O2",
            "-fno-builtin",
            "-Wl,--hash-style=both",
        ]);
        if got {
            command.arg("-fno-plt");
        }
        let output = command
            .arg(&source)
            .arg("-o")
            .arg(&path)
            .output()
            .expect("gcc is required");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let object = ElfLoader::new(0)
            .parse(&std::fs::read(&path).unwrap())
            .unwrap();
        assert!(
            object.needed_libraries.is_empty(),
            "no host runtime dependencies are permitted"
        );
        for (name, _, _) in symbols() {
            assert!(
                object
                    .undefined_symbols()
                    .any(|(_, s)| object.symbol_name(s) == Some(name)),
                "fixture did not import {name}"
            );
        }
        Self { dir, path }
    }
    fn pathname(&self, file: &str) -> CString {
        CString::new(self.dir.join(file).as_os_str().as_bytes()).unwrap()
    }
}

fn isolated(name: &str, scenario: fn(Api)) {
    if let Ok(mode) = std::env::var("FRANKENLIBC_IO_CHILD") {
        assert!(matches!(mode.as_str(), "host" | "native"));
        scenario(Api::new(mode == "native"));
        return;
    }
    for mode in ["host", "native"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FRANKENLIBC_IO_CHILD", mode)
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

fn addresses(api: Api, handle: *mut c_void) {
    let function: Function = unsafe { std::mem::transmute(api.symbol(handle, c"io_function")) };
    for (index, (name, _, expected)) in symbols().into_iter().enumerate() {
        let actual = unsafe { function(index as u32) };
        assert!(!actual.is_null(), "missing {name}");
        if api.native {
            assert_eq!(actual as usize, expected as usize, "wrong provider: {name}");
        } else {
            let name = CString::new(name).unwrap();
            assert_eq!(actual, unsafe { dlsym_oracle::host_addr(&name, expected) });
        }
    }
}

fn protocols(api: Api, got: bool) {
    let f = Fixture::new(got);
    let h = api.open(&f.path);
    addresses(api, h);
    type FileRun = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
    type DescriptorRun = unsafe extern "C" fn(*const c_char) -> c_int;
    let file: FileRun = unsafe { std::mem::transmute(api.symbol(h, c"io_file_protocol")) };
    let descriptors: DescriptorRun =
        unsafe { std::mem::transmute(api.symbol(h, c"io_descriptor_protocol")) };
    let dir = CString::new(f.dir.as_os_str().as_bytes()).unwrap();
    assert_eq!(
        unsafe { file(dir.as_ptr(), f.pathname("data").as_ptr()) },
        0,
        "C file protocol line"
    );
    assert_eq!(
        unsafe { descriptors(f.pathname("descriptors").as_ptr()) },
        0,
        "C descriptor protocol line"
    );
    api.close(h);
}

#[test]
fn io_runtime_plt_file_and_descriptor_protocols() {
    isolated("io_runtime_plt_file_and_descriptor_protocols", |api| {
        protocols(api, false)
    });
}
#[test]
fn io_runtime_got_file_and_descriptor_protocols() {
    isolated("io_runtime_got_file_and_descriptor_protocols", |api| {
        protocols(api, true)
    });
}
#[test]
fn io_runtime_dynamic_versions_match_direct_providers() {
    isolated(
        "io_runtime_dynamic_versions_match_direct_providers",
        |api| {
            let f = Fixture::new(false);
            let h = api.open(&f.path);
            addresses(api, h);
            let direct: Function = unsafe { std::mem::transmute(api.symbol(h, c"io_function")) };
            let dynamic: Dynamic = unsafe { std::mem::transmute(api.symbol(h, c"io_dynamic")) };
            for (index, (name, version, _)) in symbols().into_iter().enumerate() {
                let name = CString::new(name).unwrap();
                let version = CString::new(version).unwrap();
                for required in [std::ptr::null(), version.as_ptr()] {
                    let mut error = -1;
                    assert_eq!(
                        unsafe { dynamic(name.as_ptr(), required, &mut error) },
                        unsafe { direct(index as u32) }
                    );
                    assert_eq!(error, 0);
                }
                for rejected in [c"GLIBC_2.34", c"FRANKENLIBC_IO_MISSING_VERSION"] {
                    let mut error = -1;
                    assert!(
                        unsafe { dynamic(name.as_ptr(), rejected.as_ptr(), &mut error) }.is_null()
                    );
                    assert_eq!(error, 1);
                }
                if name.as_bytes() == b"fcntl64" {
                    let mut error = -1;
                    assert!(
                        unsafe { dynamic(name.as_ptr(), c"GLIBC_2.2.5".as_ptr(), &mut error) }
                            .is_null()
                    );
                    assert_eq!(
                        error, 1,
                        "fcntl64 must not inherit fcntl's baseline version"
                    );
                }
            }
            api.close(h);
        },
    );
}
#[test]
fn io_runtime_errors_preserve_buffers_and_file_position() {
    isolated(
        "io_runtime_errors_preserve_buffers_and_file_position",
        |api| {
            let f = Fixture::new(false);
            let h = api.open(&f.path);
            addresses(api, h);
            type Run = unsafe extern "C" fn(*const c_char) -> c_int;
            let run: Run = unsafe { std::mem::transmute(api.symbol(h, c"io_error_protocol")) };
            assert_eq!(
                unsafe { run(f.pathname("errors").as_ptr()) },
                0,
                "C error protocol line"
            );
            api.close(h);
        },
    );
}
#[test]
fn io_runtime_errno_isolated_between_native_calling_threads() {
    isolated(
        "io_runtime_errno_isolated_between_native_calling_threads",
        |api| {
            let f = Fixture::new(false);
            let h = api.open(&f.path);
            addresses(api, h);
            type Run = unsafe extern "C" fn(*mut c_int, c_int) -> usize;
            let run: Run = unsafe { std::mem::transmute(api.symbol(h, c"io_thread_errno")) };
            let arrived = AtomicI32::new(0);
            let (left, right) = std::thread::scope(|scope| {
                let a = scope.spawn(|| unsafe { run(arrived.as_ptr(), 12341) });
                let b = scope.spawn(|| unsafe { run(arrived.as_ptr(), 12342) });
                (a.join().unwrap(), b.join().unwrap())
            });
            assert_ne!(left, 0);
            assert_ne!(right, 0);
            assert_ne!(left, right);
            api.close(h);
        },
    );
}
#[test]
fn io_runtime_works_during_constructors_and_finalizers() {
    isolated(
        "io_runtime_works_during_constructors_and_finalizers",
        |api| {
            let f = Fixture::new(false);
            let h = api.open(&f.path);
            addresses(api, h);
            type Run = unsafe extern "C" fn() -> c_int;
            type Set = unsafe extern "C" fn(c_int) -> c_int;
            let run: Run = unsafe { std::mem::transmute(api.symbol(h, c"io_initial_result")) };
            let set: Set = unsafe { std::mem::transmute(api.symbol(h, c"io_set_final_fd")) };
            assert_eq!(unsafe { run() }, 0);
            // Host descriptors are real process resources, not native-loader IDs.
            // Read after dlclose to prove the plugin's finalizer used its bindings.
            let mut ends = [-1; 2];
            assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
            assert_eq!(unsafe { set(ends[1]) }, 0);
            assert_eq!(unsafe { libc::close(ends[1]) }, 0);
            api.close(h);
            let mut result = [0u8; 2];
            assert_eq!(
                unsafe { libc::read(ends[0], result.as_mut_ptr().cast(), result.len()) },
                1
            );
            assert_eq!(result[0], b'F');
            assert_eq!(
                unsafe { libc::read(ends[0], result.as_mut_ptr().cast(), result.len()) },
                0
            );
            assert_eq!(unsafe { libc::close(ends[0]) }, 0);
        },
    );
}
