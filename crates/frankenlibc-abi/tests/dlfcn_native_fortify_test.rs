//! Executed compiler fortification through the native loader, not host fallback.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use frankenlibc_abi::{dlfcn_abi as dl, fortify_abi as checked};
use frankenlibc_core::elf::ElfLoader;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

fn symbols() -> Vec<(&'static str, &'static str, *const ())> {
    macro_rules! entry {
        ($name:ident, $version:literal) => {
            (stringify!($name), $version, checked::$name as *const ())
        };
    }
    vec![
        entry!(__memcpy_chk, "GLIBC_2.3.4"),
        entry!(__memmove_chk, "GLIBC_2.3.4"),
        entry!(__memset_chk, "GLIBC_2.3.4"),
        (
            "__mempcpy_chk",
            "GLIBC_2.3.4",
            frankenlibc_abi::glibc_internal_abi::__mempcpy_chk as *const (),
        ),
        entry!(__strcpy_chk, "GLIBC_2.3.4"),
        entry!(__strncpy_chk, "GLIBC_2.3.4"),
        entry!(__strcat_chk, "GLIBC_2.3.4"),
        entry!(__strncat_chk, "GLIBC_2.3.4"),
        entry!(__stpcpy_chk, "GLIBC_2.3.4"),
        entry!(__stpncpy_chk, "GLIBC_2.4"),
        entry!(__chk_fail, "GLIBC_2.3.4"),
        entry!(__stack_chk_fail, "GLIBC_2.4"),
        entry!(__fdelt_chk, "GLIBC_2.15"),
        entry!(__read_chk, "GLIBC_2.4"),
        entry!(__pread_chk, "GLIBC_2.4"),
        entry!(__pread64_chk, "GLIBC_2.4"),
        entry!(__recv_chk, "GLIBC_2.4"),
        entry!(__recvfrom_chk, "GLIBC_2.4"),
        entry!(__poll_chk, "GLIBC_2.16"),
        entry!(__ppoll_chk, "GLIBC_2.16"),
        entry!(__open_2, "GLIBC_2.7"),
        entry!(__open64_2, "GLIBC_2.7"),
        entry!(__openat_2, "GLIBC_2.7"),
        entry!(__openat64_2, "GLIBC_2.7"),
        entry!(__sprintf_chk, "GLIBC_2.3.4"),
        entry!(__snprintf_chk, "GLIBC_2.3.4"),
        entry!(__vsprintf_chk, "GLIBC_2.3.4"),
        entry!(__vsnprintf_chk, "GLIBC_2.3.4"),
        entry!(__printf_chk, "GLIBC_2.3.4"),
        entry!(__vprintf_chk, "GLIBC_2.3.4"),
        entry!(__fprintf_chk, "GLIBC_2.3.4"),
        entry!(__vfprintf_chk, "GLIBC_2.3.4"),
        entry!(__dprintf_chk, "GLIBC_2.8"),
        entry!(__vdprintf_chk, "GLIBC_2.8"),
        entry!(__asprintf_chk, "GLIBC_2.8"),
        entry!(__vasprintf_chk, "GLIBC_2.8"),
        entry!(__fgets_chk, "GLIBC_2.4"),
        entry!(__fgets_unlocked_chk, "GLIBC_2.4"),
        entry!(__fread_chk, "GLIBC_2.7"),
        entry!(__fread_unlocked_chk, "GLIBC_2.7"),
        entry!(__explicit_bzero_chk, "GLIBC_2.25"),
    ]
}

const SOURCE: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) return __LINE__; } while (0)

int checked_protocol(const char *text, size_t n, int fd_bit) {
    char buffer[64], copied[64];
    CHECK(n == 4);
    strcpy(buffer, text); strcat(buffer, ":"); strncat(buffer, "tail", n);
    CHECK(strcmp(buffer, "head:tail") == 0);
    memset(copied, 0, n + 1); memcpy(copied, buffer, n); copied[n] = 0;
    CHECK(strcmp(copied, "head") == 0);
    memmove(copied + 1, copied, n); CHECK(memcmp(copied, "hhead", 5) == 0);
    CHECK(snprintf(buffer, sizeof buffer, "%s:%d", text, 17) == 7);
    CHECK(strcmp(buffer, "head:17") == 0);
    char *allocated = 0;
    CHECK(asprintf(&allocated, "%s/%d", text, 23) == 7);
    CHECK(strcmp(allocated, "head/23") == 0); free(allocated);
    fd_set set; FD_ZERO(&set); FD_SET(fd_bit, &set);
    CHECK(FD_ISSET(fd_bit, &set)); FD_CLR(fd_bit, &set);
    CHECK(!FD_ISSET(fd_bit, &set));
    int ends[2]; CHECK(pipe(ends) == 0);
    CHECK(write(ends[1], text, n) == (ssize_t)n);
    struct pollfd p = { ends[0], POLLIN, 0 };
    volatile nfds_t one = 1;
    CHECK(poll(&p, one, 1000) == 1 && (p.revents & POLLIN));
    CHECK(read(ends[0], buffer, n) == (ssize_t)n && memcmp(buffer, text, n) == 0);
    CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, ends) == 0);
    CHECK(send(ends[0], text, n, 0) == (ssize_t)n);
    CHECK(recv(ends[1], buffer, n, 0) == (ssize_t)n && memcmp(buffer, text, n) == 0);
    CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);
    char memory[] = "line\nlast";
    FILE *stream = fmemopen(memory, sizeof memory - 1, "r"); CHECK(stream);
    CHECK(fgets(buffer, (int)n + 2, stream) && strcmp(buffer, "line\n") == 0);
    CHECK(fread(buffer, 1, n, stream) == n && memcmp(buffer, "last", n) == 0);
    CHECK(fclose(stream) == 0);
    return 0;
}

int checked_failure(unsigned which) {
    char destination[8]; char source[32];
    memset(source, 'x', sizeof source); source[31] = 0;
    volatile size_t excessive = 9;
    if (which == 0) memcpy(destination, source, excessive);
    if (which == 1) { destination[0] = 0; strcat(destination, source); }
    if (which == 2) { fd_set set; FD_ZERO(&set); volatile int fd = FD_SETSIZE; FD_SET(fd, &set); }
    if (which == 3) { int fd = open("/dev/zero", O_RDONLY); if (fd < 0) return 1; if (read(fd, destination, excessive) < 0) return 2; close(fd); }
    __asm__ __volatile__("" : : "m"(destination) : "memory");
    return 0;
}

void *checked_dynamic(const char *name, const char *version, int *failed) {
    dlerror();
    void *p = version ? dlvsym(RTLD_DEFAULT, name, version) : dlsym(RTLD_DEFAULT, name);
    *failed = dlerror() != 0;
    __asm__ __volatile__("" : "+r"(p));
    return p;
}
"#;

struct Library {
    path: PathBuf,
    handle: *mut c_void,
    native: bool,
}
impl Library {
    fn new(native: bool, got: bool) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc-fortified-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let mut source = SOURCE.to_owned();
        for (index, (name, _, _)) in symbols().iter().enumerate() {
            source.push_str(&format!(
                "\nextern void imported_{index}(void) __asm__(\"{name}\");"
            ));
        }
        source.push_str("\nvoid *checked_direct(unsigned n) { switch(n) {");
        for index in 0..symbols().len() {
            source.push_str(&format!("case {index}: return (void *)imported_{index};"));
        }
        source.push_str("default: return 0; } }\n");
        let input = dir.join("fixture.c");
        let path = dir.join("fixture.so");
        std::fs::write(&input, source).unwrap();
        let mut command = Command::new("cc");
        command.args([
            "-shared",
            "-fPIC",
            "-nostdlib",
            "-O2",
            "-fno-builtin",
            "-U_FORTIFY_SOURCE",
            "-D_FORTIFY_SOURCE=3",
            "-fstack-protector-strong",
        ]);
        if got {
            command.arg("-fno-plt");
        }
        let built = command
            .arg(&input)
            .arg("-o")
            .arg(&path)
            .output()
            .expect("C compiler is required");
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let object = ElfLoader::new(0)
            .parse(&std::fs::read(&path).unwrap())
            .unwrap();
        assert!(object.needed_libraries.is_empty());
        for (name, _, _) in symbols() {
            assert!(
                object
                    .undefined_symbols()
                    .any(|(_, s)| object.symbol_name(s) == Some(name)),
                "missing compiled import: {name}"
            );
        }
        let name = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the compiler-created pathname is NUL-terminated; handle is
        // retained until all fixture calls complete and then closed in Drop.
        let handle = unsafe {
            if native {
                dl::dlopen(name.as_ptr(), libc::RTLD_NOW)
            } else {
                let open: unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void =
                    dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ());
                open(name.as_ptr(), libc::RTLD_NOW)
            }
        };
        assert!(!handle.is_null(), "fortified fixture failed to load");
        if native {
            assert!(
                dl::native_dso_handle_for_tests(handle),
                "host fallback is not native support"
            );
        }
        Self {
            path,
            handle,
            native,
        }
    }
    fn symbol(&self, name: &CStr) -> *mut c_void {
        // SAFETY: the handle remains owned; all names are terminated strings.
        let p = unsafe {
            if self.native {
                dl::dlsym(self.handle, name.as_ptr())
            } else {
                let lookup: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void =
                    dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ());
                lookup(self.handle, name.as_ptr())
            }
        };
        assert!(!p.is_null(), "missing {name:?} in {:?}", self.path);
        p
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: every test has finished using the live fixture before Drop.
        let result = unsafe {
            if self.native {
                dl::dlclose(self.handle)
            } else {
                let close: unsafe extern "C" fn(*mut c_void) -> c_int =
                    dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ());
                close(self.handle)
            }
        };
        assert_eq!(result, 0);
    }
}

fn child(name: &str, backend: &str, mode: &str, failure: Option<u32>) -> ExitStatus {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", name, "--nocapture"])
        .env("FL_FORTIFY_BACKEND", backend)
        .env("FRANKENLIBC_MODE", mode)
        .env_remove("LD_PRELOAD");
    if let Some(failure) = failure {
        cmd.env("FL_FORTIFY_FAILURE", failure.to_string());
    }
    let mut process = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(status) = process.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            process.kill().unwrap();
            process.wait().unwrap();
            panic!("fortified fixture timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn native_fortified_protocols_and_versioned_providers() {
    if let Ok(backend) = std::env::var("FL_FORTIFY_BACKEND") {
        for got in [false, true] {
            let library = Library::new(backend == "native", got);
            type Run = unsafe extern "C" fn(*const c_char, usize, c_int) -> c_int;
            type Direct = unsafe extern "C" fn(u32) -> *mut c_void;
            type Dynamic =
                unsafe extern "C" fn(*const c_char, *const c_char, *mut c_int) -> *mut c_void;
            // SAFETY: all signatures agree with the compiled C fixture.
            unsafe {
                let run: Run = std::mem::transmute(library.symbol(c"checked_protocol"));
                let direct: Direct = std::mem::transmute(library.symbol(c"checked_direct"));
                let dynamic: Dynamic = std::mem::transmute(library.symbol(c"checked_dynamic"));
                assert_eq!(
                    run(c"head".as_ptr(), 4, 127),
                    0,
                    "C protocol assertion line"
                );
                for (index, (name, version, expected)) in symbols().into_iter().enumerate() {
                    let name = CString::new(name).unwrap();
                    let version = CString::new(version).unwrap();
                    let provider = direct(index as u32);
                    let expected = if library.native {
                        expected.cast_mut().cast()
                    } else {
                        dlsym_oracle::host_addr(&name, expected)
                    };
                    assert_eq!(provider, expected, "wrong provider: {name:?}");
                    for version in [std::ptr::null(), version.as_ptr()] {
                        let mut failed = -1;
                        assert_eq!(dynamic(name.as_ptr(), version, &mut failed), provider);
                        assert_eq!(failed, 0);
                    }
                    for wrong in [
                        c"GLIBC_2.2.5",
                        c"GLIBC_2.34",
                        c"FRANKENLIBC_MISSING_VERSION",
                    ] {
                        let mut failed = -1;
                        assert!(dynamic(name.as_ptr(), wrong.as_ptr(), &mut failed).is_null());
                        assert_eq!(failed, 1);
                    }
                }
            }
        }
        return;
    }
    for (backend, mode) in [
        ("host", "strict"),
        ("native", "strict"),
        ("native", "hardened"),
    ] {
        assert!(
            child(
                "native_fortified_protocols_and_versioned_providers",
                backend,
                mode,
                None
            )
            .success(),
            "{backend}/{mode}"
        );
    }
}

#[test]
fn native_fortification_still_terminates_invalid_operations() {
    if let Ok(backend) = std::env::var("FL_FORTIFY_BACKEND") {
        let which: u32 = std::env::var("FL_FORTIFY_FAILURE")
            .unwrap()
            .parse()
            .unwrap();
        // SAFETY: suppress only core-file creation in this disposable child.
        unsafe {
            libc::setrlimit(
                libc::RLIMIT_CORE,
                &libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                },
            );
        }
        let library = Library::new(backend == "native", false);
        // SAFETY: C fixture signature is exact; checked calls must abort before
        // an invalid write, and the parent requires SIGABRT rather than success.
        let run: unsafe extern "C" fn(u32) -> c_int =
            unsafe { std::mem::transmute(library.symbol(c"checked_failure")) };
        let _ = unsafe { run(which) };
        panic!("fortified invalid operation returned");
    }
    for (backend, mode) in [
        ("host", "strict"),
        ("native", "strict"),
        ("native", "hardened"),
    ] {
        for which in 0..4 {
            assert_eq!(
                child(
                    "native_fortification_still_terminates_invalid_operations",
                    backend,
                    mode,
                    Some(which)
                )
                .signal(),
                Some(libc::SIGABRT),
                "{backend}/{mode}/{which}"
            );
        }
    }
}
