#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicI32;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::{
    dlfcn_abi as dl, errno_abi as errno, fortify_abi as checked, io_abi as io,
    malloc_abi as malloc, unistd_abi as unistd,
};
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

int io_fexecve_execute(int fd, char *const argv[], char *const envp[]) {
    return fexecve(fd, argv, envp);
}
int io_execveat_execute(int fd, char *const argv[], char *const envp[]) {
    return execveat(fd, "", argv, envp, AT_EMPTY_PATH);
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
    errno = 0; CHECK(lockf(-1, 123456, 1) == -1 && errno == EINVAL);
    errno = 0; CHECK(lockf64(-1, 123456, 1) == -1 && errno == EINVAL);
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
    extern void *flc_metadata_function(unsigned);
    extern void *flc_path_function(unsigned);
    if (index >= 46) return flc_path_function(index - 46);
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
        case 35: return (void *)fexecve;
        case 36: return (void *)execveat;
        default: return flc_metadata_function(index - 37);
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

fn symbols() -> [(&'static str, &'static str, *const ()); 58] {
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
        ("fexecve", "GLIBC_2.2.5", unistd::fexecve as *const ()),
        ("execveat", "GLIBC_2.34", unistd::execveat as *const ()),
        ("stat", "GLIBC_2.33", unistd::stat as *const ()),
        ("fstat", "GLIBC_2.33", unistd::fstat as *const ()),
        ("lstat", "GLIBC_2.33", unistd::lstat as *const ()),
        ("fstatat", "GLIBC_2.33", unistd::fstatat as *const ()),
        ("stat64", "GLIBC_2.33", unistd::stat64 as *const ()),
        ("fstat64", "GLIBC_2.33", unistd::fstat64 as *const ()),
        ("lstat64", "GLIBC_2.33", unistd::lstat64 as *const ()),
        ("fstatat64", "GLIBC_2.33", unistd::fstatat64 as *const ()),
        ("statx", "GLIBC_2.28", unistd::statx as *const ()),
        ("creat64", "GLIBC_2.2.5", unistd::creat64 as *const ()),
        ("access", "GLIBC_2.2.5", unistd::access as *const ()),
        ("faccessat", "GLIBC_2.4", unistd::faccessat as *const ()),
        ("getcwd", "GLIBC_2.2.5", unistd::getcwd as *const ()),
        ("chdir", "GLIBC_2.2.5", unistd::chdir as *const ()),
        ("fchdir", "GLIBC_2.2.5", unistd::fchdir as *const ()),
        ("readlink", "GLIBC_2.2.5", unistd::readlink as *const ()),
        ("readlinkat", "GLIBC_2.4", unistd::readlinkat as *const ()),
        ("free", "GLIBC_2.2.5", malloc::free as *const ()),
        (
            "__getcwd_chk",
            "GLIBC_2.4",
            checked::__getcwd_chk as *const (),
        ),
        (
            "__readlink_chk",
            "GLIBC_2.4",
            checked::__readlink_chk as *const (),
        ),
        (
            "__readlinkat_chk",
            "GLIBC_2.5",
            checked::__readlinkat_chk as *const (),
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
        // getcwd reports the physical pathname, including when TMPDIR is an alias.
        let dir = std::fs::canonicalize(dir).unwrap();
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
            "-DFLC_STAT_PLUGIN",
            "-Wl,--hash-style=both",
        ]);
        if got {
            command.arg("-fno-plt");
        }
        let output = command
            .arg(&source)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/integration/fixture_fcntl64_args.c"
            ))
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

fn pathname_protocols(name: &str, got: bool) {
    use std::os::fd::AsRawFd;

    let Ok(provider) = std::env::var("FRANKENLIBC_PATH_CHILD") else {
        let retained = std::env::temp_dir().join(format!(
            "frankenlibc-path-parents-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&retained).unwrap();
        for provider in ["host", "native"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture"])
                .env("FRANKENLIBC_PATH_CHILD", provider)
                .output()
                .unwrap();
            std::fs::write(retained.join(format!("{provider}.stdout")), &output.stdout).unwrap();
            std::fs::write(retained.join(format!("{provider}.stderr")), &output.stderr).unwrap();
            assert!(
                output.status.success(),
                "{provider}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        println!("pathname host/native protocol passed; retained {retained:?}");
        return;
    };
    assert!(matches!(provider.as_str(), "host" | "native"));
    let api = Api::new(provider == "native");
    let fixture = Fixture::new(got);
    std::fs::write(fixture.dir.join("data"), b"data").unwrap();
    std::os::unix::fs::symlink("data", fixture.dir.join("link")).unwrap();
    let mut deep = std::fs::File::open(&fixture.dir).unwrap();
    let component = "d".repeat(200);
    let mut deep_name = fixture.dir.clone();
    for _ in 0..24 {
        let child = PathBuf::from(format!("/proc/self/fd/{}", deep.as_raw_fd())).join(&component);
        std::fs::create_dir(&child).unwrap();
        deep = std::fs::File::open(&child).unwrap();
        deep_name.push(&component);
    }
    let handle = api.open(&fixture.path);
    addresses(api, handle);
    type Restore = unsafe extern "C" fn(c_int) -> c_int;
    type Run = unsafe extern "C" fn(
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
        c_int,
        *const c_char,
        c_int,
        Restore,
        *mut u32,
    ) -> c_int;
    // SAFETY: both signatures match the C fixture. The independent GNU
    // restore callback and retained deep descriptor outlive the invocation.
    let (run, restore): (Run, Restore) = unsafe {
        (
            std::mem::transmute::<*mut c_void, Run>(api.symbol(handle, c"flc_path_protocol")),
            dlsym_oracle::host_fn(c"fchdir", unistd::fchdir as *const ()),
        )
    };
    let directory = CString::new(fixture.dir.as_os_str().as_bytes()).unwrap();
    let deep_name = CString::new(deep_name.as_os_str().as_bytes()).unwrap();
    let repairs = api.native && std::env::var("FRANKENLIBC_MODE").as_deref() == Ok("hardened");
    let mut counts = [0; 3];
    // SAFETY: all paths are live NUL-terminated strings; counts is writable
    // storage for three unsigned integers. The child owns cwd changes.
    let result = unsafe {
        run(
            directory.as_ptr(),
            fixture.pathname("data").as_ptr(),
            fixture.pathname("link").as_ptr(),
            fixture.pathname("missing").as_ptr(),
            fixture.pathname("created").as_ptr(),
            deep.as_raw_fd(),
            deep_name.as_ptr(),
            c_int::from(repairs),
            restore,
            counts.as_mut_ptr(),
        )
    };
    assert_eq!(result, 0, "C pathname protocol line; counts={counts:?}");
    assert_eq!(
        counts,
        [34, if repairs { 21 } else { 22 }, u32::from(repairs)]
    );
    println!(
        "{provider} pathname protocol: counts={counts:?}; retained {:?}",
        fixture.dir
    );
    api.close(handle);
}

#[test]
fn native_pathname_plt_protocol() {
    pathname_protocols("native_pathname_plt_protocol", false);
}

#[test]
fn native_pathname_got_protocol() {
    pathname_protocols("native_pathname_got_protocol", true);
}

#[test]
fn native_cwd_review_deep_errors_and_bind_mount() {
    use std::os::fd::AsRawFd;

    let name = "native_cwd_review_deep_errors_and_bind_mount";
    let Ok(provider) = std::env::var("FRANKENLIBC_CWD_CHILD") else {
        let retained = std::env::temp_dir().join(format!(
            "frankenlibc-cwd-parents-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&retained).unwrap();
        for provider in ["host", "native"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture"])
                .env("FRANKENLIBC_CWD_CHILD", provider)
                .output()
                .unwrap();
            std::fs::write(retained.join(format!("{provider}.stdout")), &output.stdout).unwrap();
            std::fs::write(retained.join(format!("{provider}.stderr")), &output.stderr).unwrap();
            assert!(
                output.status.success(),
                "{provider}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        println!(
            "deep cwd: host/native each passed 18 cases (6 success, 12 errors); retained {retained:?}"
        );
        return;
    };
    assert!(matches!(provider.as_str(), "host" | "native"));
    let fixture = Fixture::new(false);
    let root = std::fs::canonicalize(&fixture.dir).unwrap();
    let source = root.join("source-parent/source");
    let target = root.join("bind");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir(&target).unwrap();
    let component = "d".repeat(200);
    let mut deep = std::fs::File::open(&source).unwrap();
    let mut normal_name = source.clone();
    let mut bind_name = target.clone();
    for _ in 0..24 {
        let child = PathBuf::from(format!("/proc/self/fd/{}", deep.as_raw_fd())).join(&component);
        std::fs::create_dir(&child).unwrap();
        deep = std::fs::File::open(&child).unwrap();
        normal_name.push(&component);
        bind_name.push(&component);
    }
    assert!(normal_name.as_os_str().len() > 4096 && bind_name.as_os_str().len() > 4096);
    let observer = root.join("observer.so");
    let output = Command::new("gcc")
        .args([
            "-shared",
            "-fPIC",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-builtin",
        ])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/integration/fixture_fcntl64_args.c"
        ))
        .args(["-ldl", "-pthread", "-o"])
        .arg(&observer)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let host = Api::new(false);
    let handle = host.open(&observer);
    type Cwd = unsafe extern "C" fn(*mut c_char, usize) -> *mut c_char;
    type Free = unsafe extern "C" fn(*mut c_void);
    type Errno = unsafe extern "C" fn() -> *mut c_int;
    #[repr(C)]
    struct Observation {
        status: c_int,
        setup: c_int,
        success: c_int,
        error: c_int,
        raw_error: c_int,
        guards_ok: c_int,
        fd_delta: c_int,
        same_device: c_int,
        different_inode: c_int,
        length: usize,
        path: [u8; 8192],
    }
    type Observe = unsafe extern "C" fn(
        Cwd,
        Free,
        Errno,
        *const c_char,
        *const c_char,
        *const c_char,
        c_int,
        c_int,
        c_int,
        *mut Observation,
    ) -> c_int;
    // SAFETY: the C observer has this exact signature. Each callback comes
    // from one provider, including its allocator and errno slot.
    let (observe, cwd, free, error): (Observe, Cwd, Free, Errno) = unsafe {
        let observe =
            std::mem::transmute::<*mut c_void, Observe>(host.symbol(handle, c"flc_cwd_observe"));
        let callbacks = if provider == "native" {
            (
                unistd::getcwd as Cwd,
                malloc::free as Free,
                errno::__errno_location as Errno,
            )
        } else {
            (
                dlsym_oracle::host_fn(c"getcwd", unistd::getcwd as *const ()),
                dlsym_oracle::host_fn(c"free", malloc::free as *const ()),
                dlsym_oracle::host_fn(c"__errno_location", errno::__errno_location as *const ()),
            )
        };
        (observe, callbacks.0, callbacks.1, callbacks.2)
    };
    let source = CString::new(source.as_os_str().as_bytes()).unwrap();
    let target = CString::new(target.as_os_str().as_bytes()).unwrap();
    let component = CString::new(component).unwrap();
    let before = std::env::current_dir().unwrap();
    let errors = [0, libc::EACCES, libc::EIO, libc::EINTR, libc::ENOENT, 0];
    let mut mismatches = Vec::new();
    for (policy, expected_error) in errors.into_iter().enumerate() {
        for form in 0..3 {
            // SAFETY: zero is valid for every integer and byte field.
            let mut out: Observation = unsafe { std::mem::zeroed() };
            // SAFETY: callbacks and strings outlive this synchronous call;
            // the descriptor is live and out is a writable C-layout buffer.
            let result = unsafe {
                observe(
                    cwd,
                    free,
                    error,
                    source.as_ptr(),
                    target.as_ptr(),
                    component.as_ptr(),
                    deep.as_raw_fd(),
                    policy as c_int,
                    form,
                    &mut out,
                )
            };
            let mut valid = result == 0
                && out.status == 0
                && out.setup == 0
                && out.raw_error == libc::ENAMETOOLONG
                && out.guards_ok == 1
                && out.fd_delta == 0;
            if expected_error == 0 {
                let expected = if policy == 5 {
                    &bind_name
                } else {
                    &normal_name
                }
                .as_os_str()
                .as_bytes();
                valid &= out.success == 1
                    && out.length == expected.len()
                    && out.path.get(..out.length) == Some(expected)
                    && out.path.get(out.length) == Some(&0);
            } else {
                valid &= out.success == 0 && out.error == expected_error;
            }
            if policy == 5 {
                valid &= out.same_device == 1 && out.different_inode == 1;
            }
            if !valid {
                mismatches.push(format!("policy={policy} form={form} result={result} setup={} status={} success={} errno={} raw={} guards={} fds={} length={}",
                    out.setup, out.status, out.success, out.error, out.raw_error, out.guards_ok, out.fd_delta, out.length));
            }
        }
    }
    assert_eq!(std::env::current_dir().unwrap(), before);
    host.close(handle);
    assert!(
        mismatches.is_empty(),
        "{provider}: {mismatches:#?}; retained {root:?}"
    );
    println!("{provider}: 18 cases (6 success, 12 errors); retained {root:?}");
}

#[test]
fn native_cwd_review_symlink_tmpdir() {
    let root = std::env::temp_dir().join(format!(
        "frankenlibc-cwd-alias-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::create_dir(root.join("real")).unwrap();
    std::os::unix::fs::symlink("real", root.join("alias")).unwrap();
    for provider in ["host", "native"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_pathname_plt_protocol", "--nocapture"])
            .env("FRANKENLIBC_PATH_CHILD", provider)
            .env("TMPDIR", root.join("alias"))
            .output()
            .unwrap();
        std::fs::write(root.join(format!("{provider}.stdout")), &output.stdout).unwrap();
        std::fs::write(root.join(format!("{provider}.stderr")), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "{provider}: {}\n{}; retained {root:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
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

fn metadata_protocol(api: Api, got: bool) {
    let fixture = Fixture::new(got);
    let file = std::fs::File::create(fixture.dir.join("data")).unwrap();
    file.set_len(0x1_0000_0025).unwrap();
    std::os::unix::fs::symlink("data", fixture.dir.join("link")).unwrap();
    let directory = CString::new(fixture.dir.as_os_str().as_bytes()).unwrap();
    let data = fixture.pathname("data");
    let link = fixture.pathname("link");
    let missing = fixture.pathname("missing");
    type Reference = unsafe extern "C" fn(c_int, *const c_char, *mut libc::stat, c_int) -> c_int;
    type Run = unsafe extern "C" fn(
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
        Reference,
        *mut u32,
    ) -> c_int;
    // SAFETY: the signatures match the GNU declarations and the C fixture.
    // The distinct GNU fstatat provider captures a fresh reference after each
    // query, including symlink atime changes caused by preceding traversal.
    // Plugin calls receive live paths and writable counters for the call.
    unsafe {
        let reference: Reference = dlsym_oracle::host_fn(c"fstatat", unistd::fstatat as *const ());
        let handle = api.open(&fixture.path);
        addresses(api, handle);
        let run =
            std::mem::transmute::<*mut c_void, Run>(api.symbol(handle, c"flc_metadata_protocol"));
        let mut counts = [0_u32; 2];
        let result = run(
            directory.as_ptr(),
            data.as_ptr(),
            link.as_ptr(),
            missing.as_ptr(),
            reference,
            counts.as_mut_ptr(),
        );
        assert_eq!(
            result, 0,
            "shared C metadata protocol line; native={}, completed={counts:?}",
            api.native,
        );
        assert_eq!(counts, [34, 13], "positive/error domain must execute");
        api.close(handle);
    }
}

#[test]
fn io_runtime_plt_metadata_matches_host() {
    // These queries change no process-wide state. Exercise both providers in
    // this test process so its result describes the complete comparison.
    for native in [false, true] {
        metadata_protocol(Api::new(native), false);
    }
}

#[test]
fn io_runtime_got_metadata_matches_host() {
    for native in [false, true] {
        metadata_protocol(Api::new(native), true);
    }
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
                let wrong = if name.as_bytes() == b"execveat" {
                    c"GLIBC_2.2.5"
                } else {
                    c"GLIBC_2.34"
                };
                for rejected in [wrong, c"FRANKENLIBC_IO_MISSING_VERSION"] {
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
                if matches!(
                    name.to_bytes(),
                    b"stat"
                        | b"fstat"
                        | b"lstat"
                        | b"fstatat"
                        | b"stat64"
                        | b"fstat64"
                        | b"lstat64"
                        | b"fstatat64"
                        | b"statx"
                ) {
                    let mut error = -1;
                    assert!(
                        unsafe { dynamic(name.as_ptr(), c"GLIBC_2.2.5".as_ptr(), &mut error) }
                            .is_null()
                    );
                    assert_eq!(error, 1, "modern metadata must reject the old baseline");
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
fn lseek_aliases_match_host_errors_without_repositioning() {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::FileExt;

    type Seek = unsafe extern "C" fn(c_int, i64, c_int) -> i64;
    type Errno = unsafe extern "C" fn() -> *mut c_int;
    // SAFETY: these signatures match the GNU declarations. Each resolution
    // rejects an address equal to our own implementation before any call.
    let (host_seek, host_seek64, host_errno): (Seek, Seek, Errno) = unsafe {
        (
            dlsym_oracle::host_fn(c"lseek", unistd::lseek as *const ()),
            dlsym_oracle::host_fn(c"lseek64", unistd::lseek64 as *const ()),
            dlsym_oracle::host_fn(c"__errno_location", errno::__errno_location as *const ()),
        )
    };
    let path = std::env::temp_dir().join(format!(
        "frankenlibc-lseek-retained-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.write_all(b"0123456789").unwrap();
    let duplicate = file.try_clone().unwrap();
    let mut ends = [-1; 2];
    // SAFETY: ends has space for two descriptors; successful descriptors are
    // immediately owned, so assertion unwinding closes them without unlinking.
    assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
    let (reader, writer) =
        unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
    // SAFETY: the pipe writer is live and the constant supplies one byte.
    assert_eq!(
        unsafe { libc::write(writer.as_raw_fd(), c"q".as_ptr().cast(), 1) },
        1
    );
    // SAFETY: duplicate a live fd, then close only that owned duplicate.
    let closed = unsafe { libc::dup(reader.as_raw_fd()) };
    assert!(closed >= 0);
    assert_eq!(unsafe { libc::close(closed) }, 0);
    // Resolve errno before using the closed descriptor: no subsequent setup
    // opens another fd that could reuse it.
    // SAFETY: both functions return this thread's writable errno cell.
    let (host_slot, native_slot) = unsafe { (host_errno(), errno::__errno_location()) };
    let mut mismatches = Vec::new();
    let mut observations = 0;
    for (name, native, host) in [
        ("lseek", unistd::lseek as Seek, host_seek),
        ("lseek64", unistd::lseek64 as Seek, host_seek64),
    ] {
        for (kind, fd) in [
            ("regular", file.as_raw_fd()),
            ("duplicate", duplicate.as_raw_fd()),
            ("pipe", reader.as_raw_fd()),
            ("invalid", -1),
            ("closed", closed),
        ] {
            for whence in [0, 1, 2, 3, 4, -1, 5, 123456, c_int::MIN, c_int::MAX] {
                for offset in [-9, 0, 7] {
                    // SAFETY: descriptors are either live resources or
                    // deliberately invalid; seek never dereferences a pointer.
                    // Capture each provider's errno before any further call.
                    let (expected, actual) = unsafe {
                        assert_eq!(host_seek(file.as_raw_fd(), 3, libc::SEEK_SET), 3);
                        *host_slot = 0;
                        let rc = host(fd, offset, whence);
                        let error = *host_slot;
                        let position = host_seek(file.as_raw_fd(), 0, libc::SEEK_CUR);
                        let expected = (rc, error, position);
                        assert_eq!(host_seek(file.as_raw_fd(), 3, libc::SEEK_SET), 3);
                        *native_slot = 0;
                        let rc = native(fd, offset, whence);
                        let error = *native_slot;
                        let position = host_seek(file.as_raw_fd(), 0, libc::SEEK_CUR);
                        (expected, (rc, error, position))
                    };
                    if expected != actual {
                        mismatches.push(format!(
                            "{name}/{kind} offset={offset} whence={whence}: host={expected:?} native={actual:?}"
                        ));
                    }
                    observations += 1;
                }
            }
        }
    }
    assert_eq!(observations, 300);
    let mut bytes = [0; 10];
    assert_eq!(file.read_at(&mut bytes, 0).unwrap(), bytes.len());
    assert_eq!(&bytes, b"0123456789");
    assert_eq!(file.metadata().unwrap().len(), 10);
    let mut byte = 0u8;
    // SAFETY: the pipe reader is live and byte is writable for one byte.
    assert_eq!(
        unsafe { libc::read(reader.as_raw_fd(), (&raw mut byte).cast(), 1) },
        1
    );
    assert_eq!(byte, b'q', "seek errors must not consume pipe data");
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn lockf_aliases_match_host_locks_and_errors() {
    use std::io::{BufRead, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::FileExt;
    use std::process::Stdio;

    type Lock = unsafe extern "C-unwind" fn(c_int, c_int, libc::off_t) -> c_int;
    type Fcntl = unsafe extern "C-unwind" fn(c_int, c_int, ...) -> c_int;
    type Seek = unsafe extern "C" fn(c_int, i64, c_int) -> i64;
    type Errno = unsafe extern "C" fn() -> *mut c_int;
    // SAFETY: signatures match the GNU interfaces, and each lookup rejects
    // an address belonging to the native implementation being compared.
    let (host, host64, fcntl, seek, host_errno): (Lock, Lock, Fcntl, Seek, Errno) = unsafe {
        (
            dlsym_oracle::host_fn(c"lockf", unistd::lockf as *const ()),
            dlsym_oracle::host_fn(c"lockf64", unistd::lockf64 as *const ()),
            dlsym_oracle::host_fn(c"fcntl", io::fcntl as *const ()),
            dlsym_oracle::host_fn(c"lseek", unistd::lseek as *const ()),
            dlsym_oracle::host_fn(c"__errno_location", errno::__errno_location as *const ()),
        )
    };
    if let Ok(role) = std::env::var("FRANKENLIBC_LOCKF_CHILD") {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(std::env::var_os("FRANKENLIBC_LOCKF_PATH").unwrap())
            .unwrap();
        // SAFETY: flock is fully initialized and lives through each fcntl;
        // queries/sets operate on this child's live regular-file descriptor.
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_whence = libc::SEEK_SET as _;
        if role == "probe" {
            lock.l_type = libc::F_WRLCK as _;
            // SAFETY: the live fd and initialized flock satisfy F_GETLK.
            assert_eq!(
                unsafe { fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) },
                0
            );
            println!(
                "LOCKF_RANGE={},{},{},{}",
                lock.l_type, lock.l_start, lock.l_len, lock.l_pid
            );
        } else {
            assert!(matches!(role.as_str(), "read" | "write"));
            lock.l_type = (if role == "read" {
                libc::F_RDLCK
            } else {
                libc::F_WRLCK
            }) as _;
            lock.l_start = 7;
            lock.l_len = 4;
            // SAFETY: F_SETLK consumes the initialized request synchronously.
            assert_eq!(unsafe { fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) }, 0);
            println!("LOCKF_READY");
            std::io::stdout().flush().unwrap();
            // Closing the parent's stdin pipe releases the helper naturally;
            // no forced termination or filesystem cleanup is necessary.
            std::io::stdin().read_to_end(&mut Vec::new()).unwrap();
        }
        return;
    }

    let dir = std::env::temp_dir().join(format!(
        "frankenlibc-lockf-retained-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("data");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.write_all(b"0123456789abcdef").unwrap();
    let readonly = std::fs::File::open(&path).unwrap();
    let mut ends = [-1; 2];
    // SAFETY: ends has room for both new descriptors, immediately owned below.
    assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
    // SAFETY: successful pipe returned two distinct, exclusively owned fds.
    let (reader, writer) =
        unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
    // SAFETY: writer is live and the constant has at least one readable byte.
    assert_eq!(
        unsafe { libc::write(writer.as_raw_fd(), c"q".as_ptr().cast(), 1) },
        1
    );
    // SAFETY: duplicate a live fd, then close only the new owned duplicate.
    let closed = unsafe { libc::dup(reader.as_raw_fd()) };
    assert!(closed >= 0);
    assert_eq!(unsafe { libc::close(closed) }, 0);
    // SAFETY: each provider returns its writable errno cell for this thread.
    let (host_slot, native_slot) = unsafe { (host_errno(), errno::__errno_location()) };
    let reset = || {
        // SAFETY: the initialized lock request unlocks only this process's
        // locks on its retained test file; neither seek changes its contents.
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = libc::F_UNLCK as _;
        lock.l_whence = libc::SEEK_SET as _;
        // SAFETY: file remains open and lock specifies a whole-file unlock.
        assert_eq!(unsafe { fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) }, 0);
        // SAFETY: both seeks operate on live regular-file descriptors.
        assert_eq!(unsafe { seek(file.as_raw_fd(), 7, libc::SEEK_SET) }, 7);
        // SAFETY: readonly is live; seeking does not require write access.
        assert_eq!(unsafe { seek(readonly.as_raw_fd(), 7, libc::SEEK_SET) }, 7);
    };
    let mut mismatches = Vec::new();
    let mut observations = 0;
    for (name, native, oracle) in [
        ("lockf", unistd::lockf as Lock, host),
        ("lockf64", unistd::lockf64 as Lock, host64),
    ] {
        for (kind, fd) in [
            ("regular", file.as_raw_fd()),
            ("readonly", readonly.as_raw_fd()),
            ("pipe-reader", reader.as_raw_fd()),
            ("pipe-writer", writer.as_raw_fd()),
            ("invalid", -1),
            ("closed", closed),
        ] {
            for command in [-1, 0, 1, 2, 3, 4, c_int::MIN, c_int::MAX] {
                for length in [-3, 0, 4] {
                    let mut results = Vec::new();
                    for (function, slot) in [(oracle, host_slot), (native, native_slot)] {
                        reset();
                        // SAFETY: all descriptors are live test resources or
                        // deliberately invalid; lockf takes no caller pointer.
                        let result = unsafe {
                            *slot = 0;
                            let rc = function(fd, command, length);
                            let error = if rc < 0 { *slot } else { 0 };
                            (
                                rc,
                                error,
                                seek(file.as_raw_fd(), 0, libc::SEEK_CUR),
                                seek(readonly.as_raw_fd(), 0, libc::SEEK_CUR),
                            )
                        };
                        results.push(result);
                    }
                    if results[0] != results[1] {
                        mismatches.push(format!(
                            "{name}/{kind} cmd={command} len={length}: {results:?}"
                        ));
                    }
                    observations += 1;
                }
            }
        }
    }
    assert_eq!(observations, 288);
    reset();

    let child = |role: &str| {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "lockf_aliases_match_host_locks_and_errors",
                "--nocapture",
            ])
            .env("FRANKENLIBC_LOCKF_CHILD", role)
            .env("FRANKENLIBC_LOCKF_PATH", &path);
        command
    };
    let mut conflicts = 0;
    for role in ["read", "write"] {
        let mut holder = child(role)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = std::io::BufReader::new(holder.stdout.take().unwrap());
        let mut transcript = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(
                output.read_line(&mut line).unwrap(),
                0,
                "helper never acquired lock"
            );
            transcript.push_str(&line);
            if line.contains("LOCKF_READY") {
                break;
            }
        }
        for (name, native, oracle) in [
            ("lockf", unistd::lockf as Lock, host),
            ("lockf64", unistd::lockf64 as Lock, host64),
        ] {
            for command in [libc::F_TEST, libc::F_TLOCK] {
                let mut results = Vec::new();
                for (function, slot) in [(oracle, host_slot), (native, native_slot)] {
                    // SAFETY: the regular file and errno cells remain live;
                    // both operations are nonblocking against the helper.
                    results.push(unsafe {
                        *slot = 0;
                        let rc = function(file.as_raw_fd(), command, 4);
                        (rc, if rc < 0 { *slot } else { 0 })
                    });
                }
                assert_eq!(results[0].0 == 0, role == "read" && command == libc::F_TEST);
                if results[0] != results[1] {
                    mismatches.push(format!("{name}/{role} cmd={command}: {results:?}"));
                }
                conflicts += 1;
            }
        }
        drop(holder.stdin.take());
        output.read_to_string(&mut transcript).unwrap();
        let status = holder.wait().unwrap();
        std::fs::write(dir.join(format!("holder-{role}.stdout")), &transcript).unwrap();
        assert!(status.success(), "holder {role}: {status}: {transcript}");
    }
    assert_eq!(conflicts, 8);

    let mut ranges = 0;
    for (name, native, oracle) in [
        ("lockf", unistd::lockf as Lock, host),
        ("lockf64", unistd::lockf64 as Lock, host64),
    ] {
        for length in [-3, 0, 4] {
            for (provider, function) in [("host", oracle), ("native", native)] {
                reset();
                // SAFETY: uncontended live regular file, lock length is valid.
                assert_eq!(
                    unsafe { function(file.as_raw_fd(), libc::F_TLOCK, length) },
                    0
                );
                let output = child("probe").output().unwrap();
                std::fs::write(
                    dir.join(format!("range-{name}-{length}-{provider}.stdout")),
                    &output.stdout,
                )
                .unwrap();
                std::fs::write(
                    dir.join(format!("range-{name}-{length}-{provider}.stderr")),
                    &output.stderr,
                )
                .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let text = String::from_utf8(output.stdout).unwrap();
                let raw = text
                    .split_once("LOCKF_RANGE=")
                    .unwrap()
                    .1
                    .lines()
                    .next()
                    .unwrap();
                let fields: Vec<i64> = raw.split(',').map(|v| v.parse().unwrap()).collect();
                let (start, size) = if length < 0 {
                    (7 + length, -length)
                } else {
                    (7, length)
                };
                assert_eq!(
                    fields,
                    [libc::F_WRLCK as i64, start, size, std::process::id() as i64],
                    "{name}/{provider}"
                );
                // SAFETY: file is still open and querying its offset is read-only.
                assert_eq!(unsafe { seek(file.as_raw_fd(), 0, libc::SEEK_CUR) }, 7);
                ranges += 1;
            }
        }
    }
    assert_eq!(ranges, 12);
    reset();
    let mut bytes = [0; 16];
    assert_eq!(file.read_at(&mut bytes, 0).unwrap(), bytes.len());
    assert_eq!(&bytes, b"0123456789abcdef");
    assert_eq!(file.metadata().unwrap().len(), 16);
    let mut byte = 0u8;
    // SAFETY: reader is live and byte supplies one writable byte.
    assert_eq!(
        unsafe { libc::read(reader.as_raw_fd(), (&raw mut byte).cast(), 1) },
        1
    );
    assert_eq!(byte, b'q');
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    println!(
        "lockf contract: {observations} comparisons, {conflicts} conflicts, {ranges} ranges passed; retained {dir:?}"
    );
}

#[test]
fn posix_fallocate_aliases_match_host_ranges_and_errors() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::FileExt;

    type Allocate = unsafe extern "C" fn(c_int, i64, i64) -> c_int;
    type Seek = unsafe extern "C" fn(c_int, i64, c_int) -> i64;
    type Errno = unsafe extern "C" fn() -> *mut c_int;
    // SAFETY: these GNU signatures are exact on LP64. The resolver rejects
    // an address belonging to the native implementation before any call.
    let (host, host64, seek, host_errno): (Allocate, Allocate, Seek, Errno) = unsafe {
        (
            dlsym_oracle::host_fn(c"posix_fallocate", unistd::posix_fallocate as *const ()),
            dlsym_oracle::host_fn(c"posix_fallocate64", unistd::posix_fallocate64 as *const ()),
            dlsym_oracle::host_fn(c"lseek", unistd::lseek as *const ()),
            dlsym_oracle::host_fn(c"__errno_location", errno::__errno_location as *const ()),
        )
    };
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc-posix-allocation-retained-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let directory = std::fs::File::open(&dir).unwrap();
    let mut resources = Vec::new();
    for name in ["host", "native"] {
        let path = dir.join(name);
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let readonly = std::fs::File::open(&path).unwrap();
        let append = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        let mut ends = [-1; 2];
        // SAFETY: ends provides space for two new descriptors, owned below.
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        // SAFETY: successful pipe returned two distinct, exclusively owned fds.
        let (reader, writer) =
            unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
        // SAFETY: writer is live and the constant provides one readable byte.
        assert_eq!(
            unsafe { libc::write(writer.as_raw_fd(), c"q".as_ptr().cast(), 1) },
            1
        );
        resources.push((file, readonly, append, reader, writer));
    }
    // Close only a fresh duplicate after all other fd setup, avoiding reuse.
    // SAFETY: the source descriptor is live; close consumes only its duplicate.
    let closed = unsafe { libc::dup(directory.as_raw_fd()) };
    assert!(closed >= 0);
    assert_eq!(unsafe { libc::close(closed) }, 0);
    // SAFETY: both providers return this thread's writable errno cell.
    let slots = unsafe { [host_errno(), errno::__errno_location()] };
    let seed = b"0123456789abcdef";
    let mut mismatches = Vec::new();
    let mut observations = 0;
    let mut successes = 0;
    for (name, oracle, native) in [
        ("posix_fallocate", host, unistd::posix_fallocate as Allocate),
        (
            "posix_fallocate64",
            host64,
            unistd::posix_fallocate64 as Allocate,
        ),
    ] {
        for kind in 0..8 {
            for offset in [-1, 0, 7, 31, i64::MIN] {
                for length in [-1, 0, 1, 4, i64::MIN] {
                    let mut results = Vec::new();
                    for (index, function) in [oracle, native].into_iter().enumerate() {
                        let (file, readonly, append, reader, writer) = &resources[index];
                        file.set_len(seed.len() as u64).unwrap();
                        file.write_all_at(seed, 0).unwrap();
                        for fd in [file.as_raw_fd(), readonly.as_raw_fd(), append.as_raw_fd()] {
                            // SAFETY: every fd is an open regular-file description.
                            assert_eq!(unsafe { seek(fd, 3, libc::SEEK_SET) }, 3);
                        }
                        let fd = [
                            file.as_raw_fd(),
                            readonly.as_raw_fd(),
                            append.as_raw_fd(),
                            reader.as_raw_fd(),
                            writer.as_raw_fd(),
                            directory.as_raw_fd(),
                            -1,
                            closed,
                        ][kind];
                        // SAFETY: descriptors are live test resources or deliberately
                        // invalid, and allocation takes no caller pointer. Capture
                        // errno immediately; these interfaces return errors directly.
                        let (rc, error) = unsafe {
                            *slots[index] = 0x3bad;
                            let rc = function(fd, offset, length);
                            (rc, *slots[index])
                        };
                        let size = file.metadata().unwrap().len();
                        assert!(size <= 35);
                        let mut bytes = vec![0; size as usize];
                        file.read_exact_at(&mut bytes, 0).unwrap();
                        assert!(
                            bytes.starts_with(seed),
                            "{name}/{index}: existing data changed"
                        );
                        assert!(bytes[seed.len()..].iter().all(|&b| b == 0));
                        let expected_size = if rc == 0 {
                            16.max(offset + length) as u64
                        } else {
                            16
                        };
                        assert_eq!(size, expected_size, "{name}/{index}");
                        // SAFETY: all three regular-file descriptions remain live.
                        let positions = unsafe {
                            [
                                seek(file.as_raw_fd(), 0, libc::SEEK_CUR),
                                seek(readonly.as_raw_fd(), 0, libc::SEEK_CUR),
                                seek(append.as_raw_fd(), 0, libc::SEEK_CUR),
                            ]
                        };
                        assert_eq!(positions, [3; 3], "allocation must not reposition");
                        assert_eq!(error, 0x3bad, "{name}/{index}: errno changed");
                        results.push((rc, error, positions, bytes));
                    }
                    successes += usize::from(results[0].0 == 0);
                    if results[0] != results[1] {
                        mismatches.push(format!(
                            "{name}/fd-kind={kind} offset={offset} len={length}: {results:?}"
                        ));
                    }
                    observations += 1;
                }
            }
        }
    }
    assert_eq!(observations, 400);
    assert_eq!(successes, 24, "positive file allocations must execute");
    for (_, _, _, reader, _) in &resources {
        let mut byte = 0u8;
        // SAFETY: each live pipe reader supplies one queued byte into byte.
        assert_eq!(
            unsafe { libc::read(reader.as_raw_fd(), (&raw mut byte).cast(), 1) },
            1
        );
        assert_eq!(byte, b'q', "allocation must not consume pipe data");
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    println!(
        "posix allocation contract: {observations} comparisons, {successes} successes passed; retained {dir:?}"
    );
}

#[test]
fn fexecve_matches_host_for_descriptor_execution() {
    let f = FdExecFixture::new();
    type Errno = unsafe extern "C" fn() -> *mut c_int;
    // SAFETY: the resolver checks that these GNU addresses differ from ours;
    // the signatures are the exact LP64 C interfaces used by the fixture.
    let (host, host_errno): (FdExecute, Errno) = unsafe {
        (
            dlsym_oracle::host_fn(c"fexecve", unistd::fexecve as *const ()),
            dlsym_oracle::host_fn(c"__errno_location", errno::__errno_location as *const ()),
        )
    };
    let mut transcript = String::new();
    let mut mismatches = Vec::new();
    let mut cases = 0;
    let mut successes = 0;
    for form in 0..4 {
        for policy in 0..4 {
            let expected = f.observe(host, host_errno, form, policy, 0);
            expected.check(
                form,
                if policy == 3 {
                    Some(libc::EACCES)
                } else {
                    None
                },
            );
            let actual = f.observe(unistd::fexecve, errno::__errno_location, form, policy, 0);
            transcript.push_str(&format!(
                "form={form} policy={policy}: GNU={expected:?} native={actual:?}\n"
            ));
            if actual != expected {
                mismatches.push(format!(
                    "form={form} policy={policy}: {actual:?} != {expected:?}"
                ));
            }
            successes += usize::from(policy != 3);
            cases += 1;
        }
        for invalid in 1..=4 {
            let expected = f.observe(host, host_errno, form, 0, invalid);
            expected.check(
                form,
                Some(if invalid == 4 {
                    libc::EBADF
                } else {
                    libc::EINVAL
                }),
            );
            let actual = f.observe(unistd::fexecve, errno::__errno_location, form, 0, invalid);
            transcript.push_str(&format!(
                "form={form} invalid={invalid}: GNU={expected:?} native={actual:?}\n"
            ));
            if actual != expected {
                mismatches.push(format!(
                    "form={form} invalid={invalid}: {actual:?} != {expected:?}"
                ));
            }
            cases += 1;
        }
    }
    std::fs::write(f.dir.join("direct-observations.txt"), transcript).unwrap();
    assert_eq!((cases, successes), (32, 12));
    assert!(
        mismatches.is_empty(),
        "{} descriptor-exec mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    println!(
        "fd exec direct: {cases} comparisons, {successes} image replacements passed; retained {:?}",
        f.dir
    );
}

#[test]
fn native_descriptor_exec_plt_and_got_replace_images() {
    let f = FdExecFixture::new();
    let host_api = Api::new(false);
    let host_fixture = Fixture::new(false);
    let host_handle = host_api.open(&host_fixture.path);
    // SAFETY: the lookup is the exact GNU errno interface, not our own provider.
    let host_errno: unsafe extern "C" fn() -> *mut c_int =
        unsafe { dlsym_oracle::host_fn(c"__errno_location", errno::__errno_location as *const ()) };
    let mut cases = 0;
    let mut transcript = String::new();
    for got in [false, true] {
        let native_api = Api::new(true);
        let native_fixture = Fixture::new(got);
        let handle = native_api.open(&native_fixture.path);
        addresses(native_api, handle);
        for name in [c"io_fexecve_execute", c"io_execveat_execute"] {
            // SAFETY: both fixture exports have FdExecute's exact signature.
            // The host fixture resolves GNU imports; native handle/address
            // checks above forbid host fallback for the native fixture.
            let (host, native): (FdExecute, FdExecute) = unsafe {
                (
                    std::mem::transmute::<*mut c_void, FdExecute>(
                        host_api.symbol(host_handle, name),
                    ),
                    std::mem::transmute::<*mut c_void, FdExecute>(native_api.symbol(handle, name)),
                )
            };
            for form in 0..4 {
                for policy in 0..2 {
                    let expected = f.observe(host, host_errno, form, policy, 0);
                    let actual = f.observe(native, errno::__errno_location, form, policy, 0);
                    expected.check(form, None);
                    actual.check(form, None);
                    transcript.push_str(&format!("got={got} name={name:?} form={form} policy={policy}: GNU={expected:?} native={actual:?}\n"));
                    assert_eq!(actual, expected);
                    cases += 1;
                }
            }
        }
        native_api.close(handle);
    }
    host_api.close(host_handle);
    std::fs::write(f.dir.join("native-observations.txt"), transcript).unwrap();
    assert_eq!(cases, 32);
    println!(
        "native fd exec: {cases} actual PLT/GOT image replacements passed; retained {:?}",
        f.dir
    );
}

type FdExecute = unsafe extern "C" fn(c_int, *const *const c_char, *const *const c_char) -> c_int;

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
struct FdExecObservation {
    status: c_int,
    returned: c_int,
    result: c_int,
    error: c_int,
    stage: c_int,
    flags: c_int,
    position: libc::c_long,
    output: [u8; 64],
}
impl FdExecObservation {
    fn check(&self, form: c_int, error: Option<c_int>) {
        assert_eq!(
            self.stage, 0,
            "kernel fixture precondition failed: {self:?}"
        );
        assert_eq!(self.flags, form & 1, "parent CLOEXEC changed");
        assert_eq!(
            self.position,
            if form & 2 != 0 { -1 } else { 7 },
            "parent position changed"
        );
        if let Some(error) = error {
            assert_eq!(
                (self.status, self.returned, self.result, self.error),
                (0, 1, -1, error)
            );
            assert_eq!(self.output, [0; 64]);
        } else {
            assert_eq!(
                (self.status, self.returned, self.result, self.error),
                (37 << 8, 0, 0, 0)
            );
            assert_eq!(&self.output[..19], b"FD_EXEC_PAYLOAD_OK\n");
            assert!(self.output[19..].iter().all(|&b| b == 0));
        }
    }
}

type FdObserve = unsafe extern "C" fn(
    FdExecute,
    unsafe extern "C" fn() -> *mut c_int,
    *const c_char,
    *const c_char,
    c_int,
    c_int,
    c_int,
    *mut FdExecObservation,
) -> c_int;

struct FdExecFixture {
    dir: PathBuf,
    payload: CString,
    api: Api,
    handle: *mut c_void,
    observe_fn: FdObserve,
}
impl FdExecFixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc-fd-exec-retained-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/integration/fixture_spawn_concurrent_fork.c");
        let payload = dir.join("payload");
        let library = dir.join("protocol.so");
        for (name, flags, output) in [
            (
                "payload",
                vec![
                    "-DFLC_FDEXEC_STATIC_PAYLOAD",
                    "-ffreestanding",
                    "-fno-stack-protector",
                    "-fno-pie",
                    "-no-pie",
                    "-nostdlib",
                    "-static",
                ],
                &payload,
            ),
            (
                "protocol",
                vec![
                    "-DFLC_FDEXEC_LIBRARY",
                    "-shared",
                    "-fPIC",
                    "-pthread",
                    "-ldl",
                ],
                &library,
            ),
        ] {
            let args = Command::new("gcc")
                .args(["-O2", "-Wall", "-Wextra", "-Werror", "-fno-builtin"])
                .args(flags)
                .arg(&source)
                .arg("-o")
                .arg(output)
                .output()
                .unwrap();
            std::fs::write(dir.join(format!("{name}.build.stdout")), &args.stdout).unwrap();
            std::fs::write(dir.join(format!("{name}.build.stderr")), &args.stderr).unwrap();
            assert!(
                args.status.success(),
                "gcc {name}: {}",
                String::from_utf8_lossy(&args.stderr)
            );
        }
        let headers = Command::new("readelf")
            .args(["-l", "--wide"])
            .arg(&payload)
            .output()
            .unwrap();
        std::fs::write(dir.join("payload.headers"), &headers.stdout).unwrap();
        assert!(headers.status.success());
        assert!(
            !String::from_utf8_lossy(&headers.stdout).contains("INTERP"),
            "proc-free payload must have no interpreter"
        );
        let api = Api::new(false);
        let handle = api.open(&library);
        // SAFETY: the C fixture's observed struct and callback types exactly
        // match their repr(C)/extern-C definitions above and outlive each call.
        let observe_fn: FdObserve =
            unsafe { std::mem::transmute(api.symbol(handle, c"fl_fdexec_observe")) };
        let payload = CString::new(payload.as_os_str().as_bytes()).unwrap();
        Self {
            dir,
            payload,
            api,
            handle,
            observe_fn,
        }
    }
    fn observe(
        &self,
        execute: FdExecute,
        error_slot: unsafe extern "C" fn() -> *mut c_int,
        form: c_int,
        policy: c_int,
        invalid: c_int,
    ) -> FdExecObservation {
        let mut out = FdExecObservation {
            status: 0,
            returned: 0,
            result: 0,
            error: 0,
            stage: 0,
            flags: 0,
            position: 0,
            output: [0; 64],
        };
        // SAFETY: callbacks remain loaded, the filename is NUL-terminated,
        // output is writable repr(C) storage, and this unprivileged profile
        // uses only policies 0..4 (no chroot). The fixture waits for its child.
        assert_eq!(
            unsafe {
                (self.observe_fn)(
                    execute,
                    error_slot,
                    self.payload.as_ptr(),
                    std::ptr::null(),
                    form,
                    policy,
                    invalid,
                    &mut out,
                )
            },
            0,
            "descriptor-exec fixture setup"
        );
        out
    }
}
impl Drop for FdExecFixture {
    fn drop(&mut self) {
        self.api.close(self.handle);
    }
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
